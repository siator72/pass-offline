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
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.flow.first
import org.json.JSONArray
import org.json.JSONObject
import proton.android.pass.crypto.api.context.EncryptionContext
import proton.android.pass.crypto.api.context.EncryptionContextProvider
import proton.android.pass.data.api.usecases.ItemTypeFilter
import proton.android.pass.data.api.usecases.ObserveItems
import proton.android.pass.domain.Item
import proton.android.pass.domain.ItemState
import proton.android.pass.domain.ItemType
import proton.android.pass.domain.ShareSelection
import javax.inject.Inject

/**
 * Offline backup: serializes every item (logins with decrypted passwords and
 * TOTP, passkeys, notes, aliases, cards) into a JSON document and writes it to
 * a user-chosen SAF location (local export) — no Proton server involved.
 */
class ExportBackupUseCase @Inject constructor(
    private val observeItems: ObserveItems,
    private val encryptionContextProvider: EncryptionContextProvider
) {

    suspend operator fun invoke(context: Context, treeUri: android.net.Uri): Result<Int> = runCatching {
        val items = observeItems(
            selection = ShareSelection.AllShares,
            itemState = ItemState.Active,
            filter = ItemTypeFilter.All,
            includeHidden = false
        ).first()

        val root = JSONArray()
        for (item in items) {
            root.put(item.toJson(encryptionContextProvider))
        }

        val doc = JSONObject()
            .put("format", "pass-offline-backup")
            .put("version", 1)
            .put("exportedAt", System.currentTimeMillis())
            .put("items", root)

        val dir = DocumentFile.fromTreeUri(context, treeUri)
            ?: throw IllegalStateException("Invalid backup directory")
        val name = "pass-backup-${System.currentTimeMillis()}.json"
        val target = dir.createFile("application/json", name)
            ?: throw IllegalStateException("Cannot create backup file")
        context.contentResolver.openOutputStream(target.uri)?.use { os ->
            os.write(doc.toString().toByteArray(Charsets.UTF_8))
        } ?: throw IllegalStateException("Cannot open backup file for writing")
        root.length()
    }

    private suspend fun Item.toJson(provider: EncryptionContextProvider): JSONObject {
        val self = this
        return provider.withEncryptionContextSuspendable {
            val ctx = this
            val obj = JSONObject()
            obj.put("shareId", self.shareId.id)
            obj.put("itemId", self.id.id)
            obj.put("title", ctx.decrypt(self.title))
            obj.put("note", ctx.decrypt(self.note))
            obj.put("createTime", self.createTime.toEpochMilliseconds())
            obj.put("modifyTime", self.modificationTime.toEpochMilliseconds())
            obj.putTypeFields(ctx, self.itemType)
            obj
        }
    }

    private fun JSONObject.putTypeFields(ctx: EncryptionContext, type: ItemType) {
        when (type) {
            is ItemType.Login -> put(
                "login", JSONObject()
                    .put("email", type.itemEmail)
                    .put("username", type.itemUsername)
                    .put("password", ctx.decrypt(type.password))
                    .put("totp", ctx.decrypt(type.primaryTotp))
                    .put("websites", JSONArray(type.websites))
                    .put("passkeys", JSONArray().apply {
                        for (pk in type.passkeys) {
                            val pkObj = JSONObject()
                            pkObj.put("id", pk.id.value)
                            pkObj.put("domain", pk.domain)
                            pkObj.put("rpId", pk.rpId)
                            pkObj.put("rpName", pk.rpName)
                            pkObj.put("userName", pk.userName)
                            pkObj.put("userDisplayName", pk.userDisplayName)
                            pkObj.put("createTime", pk.createTime.toEpochMilliseconds())
                            put(pkObj)
                        }
                    })
            )
            is ItemType.Note -> put("noteText", ctx.decrypt(type.text))
            is ItemType.Alias -> put("aliasEmail", type.aliasEmail)
            is ItemType.CreditCard -> put(
                "creditCard", JSONObject()
                    .put("cardNumber", ctx.decrypt(type.number))
                    .put("cvv", ctx.decrypt(type.cvv))
                    .put("cardHolder", type.cardHolder)
                    .put("expirationDate", type.expirationDate)
                    .put("pin", ctx.decrypt(type.pin))
            )
            else -> {}
        }
    }
}
