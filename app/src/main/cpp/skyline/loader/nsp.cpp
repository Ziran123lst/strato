// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include <kernel/types/KProcess.h>
#include <vfs/ticket.h>
#include "nca.h"
#include "nsp.h"

namespace skyline::loader {
    static void ExtractTickets(const std::shared_ptr<vfs::PartitionFileSystem>& dir, const std::shared_ptr<crypto::KeyStore> &keyStore) {
        std::vector<vfs::Ticket> tickets;

        auto dirContent{dir->OpenDirectory("", {false, true})};
        for (const auto &entry : dirContent->Read()) {
            if (entry.name.substr(entry.name.find_last_of('.') + 1) == "tik")
                tickets.emplace_back(dir->OpenFile(entry.name));
        }

        for (auto ticket : tickets) {
            auto titleKey{span(ticket.titleKeyBlock).subspan(0, 16).as<crypto::KeyStore::Key128>()};
            keyStore->PopulateTitleKey(ticket.rightsId, titleKey);
        }
    }

    NspLoader::NspLoader(const std::shared_ptr<vfs::Backing> &backing, const std::shared_ptr<crypto::KeyStore> &keyStore) : nsp(std::make_shared<vfs::PartitionFileSystem>(backing)) {
        ExtractTickets(nsp, keyStore);

        auto root{nsp->OpenDirectory("", {false, true})};
        for (const auto &entry : root->Read()) {
            if (entry.name.substr(entry.name.find_last_of('.') + 1) != "nca")
                continue;

            try {
                auto nca{vfs::NCA(nsp->OpenFile(entry.name), keyStore)};

                if (nca.contentType == vfs::NcaContentType::Program && nca.romFs != nullptr && nca.exeFs != nullptr)
                    programNca = std::move(nca);
                else if (nca.contentType == vfs::NcaContentType::Control && nca.romFs != nullptr)
                    controlNca = std::move(nca);
            } catch (const loader_exception &e) {
                // Eden/yuzu-compatible: an NCA that cannot be decrypted or parsed
                // (e.g. missing header/title keys) must not invalidate the whole
                // container. Log it, keep scanning, and let the entry display with
                // filename fallback metadata.
                LOGW("NSP: skipping NCA '{}': {}", entry.name, e.what());
                continue;
            } catch (const std::exception &e) {
                LOGW("NSP: skipping NCA '{}': {}", entry.name, e.what());
                continue;
            }
        }

        // Eden/yuzu-compatible graceful degradation: a missing program NCA, control
        // NCA or control.nacp no longer invalidates the container. The entry will
        // still be listed (metadata falls back to the file name) and only fails at
        // launch time when the program data is actually needed.
        if (programNca) {
            romFs = programNca->romFs;
        }

        if (controlNca && controlNca->romFs) {
            controlRomFs = std::make_shared<vfs::RomFileSystem>(controlNca->romFs);
            auto nacpFile{controlRomFs->OpenFile("control.nacp")};
            if (nacpFile)
                nacp.emplace(nacpFile);
        }

        LOGI("NSP loaded: programNCA={}, controlNCA={}, nacp={}, fileSize={} bytes", programNca.has_value(), controlNca.has_value(), nacp.has_value(), backing->size);
    }

    void *NspLoader::LoadProcessData(const std::shared_ptr<kernel::type::KProcess> &process, const DeviceState &state) {
        if (!programNca || !programNca->exeFs)
            throw loader_exception(LoaderResult::ParsingError);

        process->npdm = vfs::NPDM(programNca->exeFs->OpenFile("main.npdm"));
        return NcaLoader::LoadExeFs(this, programNca->exeFs, process, state);
    }

    std::vector<u8> NspLoader::GetIcon(language::ApplicationLanguage language) {
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
