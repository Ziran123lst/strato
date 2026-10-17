// SPDX-License-Identifier: MPL-2.0
// Copyright © 2020 Skyline Team and Contributors (https://github.com/skyline-emu/)

#include <algorithm>
#include <vfs/os_filesystem.h>
#include "key_store.h"

namespace skyline::crypto {
    KeyStore::KeyStore(const std::string &rootPath) {
        vfs::OsFileSystem root(rootPath);
        if (root.FileExists("title.keys"))
            ReadPairs(root.OpenFile("title.keys"), &KeyStore::PopulateTitleKeys);
        if (root.FileExists("prod.keys"))
            ReadPairs(root.OpenFile("prod.keys"), &KeyStore::PopulateKeys);
    }

    void KeyStore::ReadPairs(const std::shared_ptr<vfs::Backing> &backing, ReadPairsCallback callback) {
        std::vector<char> fileContent(backing->size);
        backing->Read(span(fileContent));

        // Normalize Windows line endings (\r\n -> \n) so hex values don't carry a trailing \r
        fileContent.erase(std::remove(fileContent.begin(), fileContent.end(), '\r'), fileContent.end());

        auto parseLine = [&](std::vector<char>::iterator start, std::vector<char>::iterator end) {
            // Skip empty lines and comment lines
            if (start == end || *start == ';' || *start == '#')
                return;

            auto keyEnd{std::find(start, end, '=')};
            if (keyEnd == end)
                return; // Skip lines without '=' instead of throwing

            std::string_view key(&*start, static_cast<size_t>(keyEnd - start));
            std::string_view value(&*(keyEnd + 1), static_cast<size_t>(end - keyEnd - 1));

            // Trim surrounding whitespace
            while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);

            if (!key.empty() && !value.empty())
                (this->*callback)(key, value);
        };

        auto lineStart{fileContent.begin()};
        std::vector<char>::iterator lineEnd;
        while ((lineEnd = std::find(lineStart, fileContent.end(), '\n')) != fileContent.end()) {
            parseLine(lineStart, lineEnd);
            lineStart = lineEnd + 1;
        }
        // Handle last line without trailing newline
        if (lineStart != fileContent.end())
            parseLine(lineStart, fileContent.end());
    }

    void KeyStore::PopulateTitleKeys(std::string_view keyName, std::string_view value) {
        Key128 key{util::HexStringToArray<16>(keyName)};
        Key128 valueArray{util::HexStringToArray<16>(value)};
        titleKeys.emplace(key, valueArray);
    }

    void KeyStore::PopulateTitleKey(Key128 keyName, Key128 value) {
        if (!titleKeys.contains(keyName))
            titleKeys.emplace(keyName, value);
    }

    void KeyStore::PopulateKeys(std::string_view keyName, std::string_view value) {
        {
            auto it{key256Names.find(keyName)};
            if (it != key256Names.end()) {
                it->second = headerKey = util::HexStringToArray<32>(value);
                return;
            }
        }

        if (keyName.size() > 2) {
            auto it{indexedKey128Names.find(keyName.substr(0, keyName.size() - 2))};
            if (it != indexedKey128Names.end()) {
                size_t index{std::stoul(std::string(keyName.substr(it->first.size())), nullptr, 16)};
                it->second[index] = util::HexStringToArray<16>(value);
            }
        }
    }
}
