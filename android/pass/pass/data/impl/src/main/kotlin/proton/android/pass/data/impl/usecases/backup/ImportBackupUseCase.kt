/*
 * Copyright (c) 2023-2026 Proton AG
 * This file is part of Proton AG and Proton Pass.
 *
 * Proton Pass is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Proton Pass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 */

package proton.android.pass.data.impl.usecases.backup

import android.content.Context
import org.json.JSONObject
import javax.inject.Inject

/**
 * Reads a previously exported offline backup file and validates its structure.
 * Restoring items into the local store is delegated to the caller (ViewModel)
 * which maps each entry through the existing item-create use cases.
 */
class ImportBackupUseCase @Inject constructor() {

    data class BackupEntry(
        val shareId: String,
        val itemId: String,
        val title: String,
        val note: String,
        val itemType: String,
        val totp: String?,
        val passkeys: String
    )

    suspend operator fun invoke(context: Context, fileUri: android.net.Uri): Result<List<BackupEntry>> = runCatching {
        val text = context.contentResolver.openInputStream(fileUri)?.use { ins ->
            ins.readBytes().toString(Charsets.UTF_8)
        } ?: throw IllegalStateException("Cannot open backup file")

        val doc = JSONObject(text)
        require(doc.getString("format") == "pass-offline-backup") { "Unsupported backup format" }
        val items = doc.getJSONArray("items")
        List(items.length()) { i ->
            val o = items.getJSONObject(i)
            BackupEntry(
                shareId = o.optString("shareId"),
                itemId = o.optString("itemId"),
                title = o.optString("title"),
                note = o.optString("note"),
                itemType = o.optString("itemType"),
                totp = o.optString("totp", "").ifEmpty { null },
                passkeys = o.optString("passkeys", "[]")
            )
        }
    }
}
