// SPDX-License-Identifier: MPL-2.0
// Copyright © 2021 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include <common.h>
#include <kernel/types/KProcess.h>
#include <vfs/region_backing.h>
#include "nca.h"
#include "xci.h"

namespace skyline::loader {
    XciLoader::XciLoader(const std::shared_ptr<vfs::Backing> &backing, const std::shared_ptr<crypto::KeyStore> &keyStore) {
        header = backing->Read<GamecardHeader>();

        // Some XCI dumps carry up to 0x1000 bytes of initial data before the gamecard
        // header (eden/yuzu retry the read at that offset). Retry before giving up.
        if (header.magic != util::MakeMagic<u32>("HEAD") && backing->size >= 0x1000 + sizeof(GamecardHeader)) {
            auto offsetBacking{std::make_shared<vfs::RegionBacking>(backing, 0x1000, backing->size - 0x1000)};
            header = offsetBacking->Read<GamecardHeader>();
        }

        if (header.magic != util::MakeMagic<u32>("HEAD"))
            throw exception("Invalid XCI file");

        xci = std::make_shared<vfs::PartitionFileSystem>(std::make_shared<vfs::RegionBacking>(backing, header.hfs0PartitionOffset, header.hfs0HeaderSize * sizeof(u32)));

        auto root{xci->OpenDirectory("", {false, true})};
        for (const auto &entry : root->Read()) {
            auto entryDir{std::make_shared<vfs::PartitionFileSystem>(xci->OpenFile(entry.name))};
            if (entry.name == "secure")
                secure = entryDir;
            else if (entry.name == "normal")
                normal = entryDir;
            else if (entry.name == "update")
                update = entryDir;
            else if (entry.name == "logo")
                logo = entryDir;
        }

        if (!secure)
            throw exception("Corrupted secure partition");

        root = secure->OpenDirectory("", {false, true});
        for (const auto &entry : root->Read()) {
            if (entry.name.substr(entry.name.find_last_of('.') + 1) != "nca")
                continue;

            try {
                auto nca{vfs::NCA(secure->OpenFile(entry.name), keyStore, true)};

                if (nca.contentType == vfs::NcaContentType::Program && nca.romFs != nullptr && nca.exeFs != nullptr)
                    programNca = std::move(nca);
                else if (nca.contentType == vfs::NcaContentType::Control && nca.romFs != nullptr)
                    controlNca = std::move(nca);
            } catch (const loader_exception &e) {
                // Eden/yuzu-compatible: an NCA that cannot be decrypted or parsed
                // must not invalidate the whole container. Log it, keep scanning.
                LOGW("XCI: skipping NCA '{}': {}", entry.name, e.what());
                continue;
            } catch (const std::exception &e) {
                LOGW("XCI: skipping NCA '{}': {}", entry.name, e.what());
                continue;
            }
        }

        // Graceful degradation: a missing program/control NCA or control.nacp
        // no longer invalidates the container. Entry is listed with filename fallback.
        if (programNca)
            romFs = programNca->romFs;

        if (controlNca && controlNca->romFs) {
            controlRomFs = std::make_shared<vfs::RomFileSystem>(controlNca->romFs);
            auto nacpFile{controlRomFs->OpenFile("control.nacp")};
            if (nacpFile)
                nacp.emplace(nacpFile);
        }

        LOGI("XCI loaded: programNCA={}, controlNCA={}, nacp={}, fileSize={} bytes", programNca.has_value(), controlNca.has_value(), nacp.has_value(), backing->size);
    }

    void *XciLoader::LoadProcessData(const std::shared_ptr<kernel::type::KProcess> &process, const DeviceState &state) {
        if (!programNca || !programNca->exeFs)
            throw loader_exception(LoaderResult::ParsingError);

        process->npdm = vfs::NPDM(programNca->exeFs->OpenFile("main.npdm"));
        return NcaLoader::LoadExeFs(this, programNca->exeFs, process, state);
    }

    std::vector<u8> XciLoader::GetIcon(language::ApplicationLanguage language) {
        if (controlRomFs == nullptr)
            return std::vector<u8>();

        std::shared_ptr<vfs::Backing> icon{};

        auto iconName{fmt::format("icon_{}.dat", language::ToString(language))};
        if (!(icon = controlRomFs->OpenFileUnchecked(iconName, {true, false, false}))) {
            if (nacp)
                iconName = fmt::format("icon_{}.dat", language::ToString(nacp->GetFirstSupportedTitleLanguage()));
            icon = controlRomFs->OpenFileUnchecked(iconName, {true, false, false});
        }

        if (icon == nullptr)
            return std::vector<u8>();

        std::vector<u8> buffer(icon->size);
        icon->Read(buffer);
        return buffer;
    }
}
