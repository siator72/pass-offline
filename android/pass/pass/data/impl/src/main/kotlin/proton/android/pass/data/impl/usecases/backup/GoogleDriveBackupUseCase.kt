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
import org.json.JSONObject
import javax.inject.Inject

/**
 * Google Drive backup replacement for Proton server sync.
 *
 * The user connects their OWN Google account by pasting a Drive OAuth access
 * token (or configuring the built-in picker); backups are encrypted
 * client-side with AES-GCM using a passphrase (PBKDF2 310k iterations) so the
 * Drive provider never sees plaintext secrets. Uses the `drive.file` scope
 * only: the app can see files it created, nothing else.
 */
class GoogleDriveBackupUseCase @Inject constructor() {

    data class DriveConfig(val accessToken: String)

    private fun encrypt(text: String, passphrase: CharArray): ByteArray {
        val salt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val spec = javax.crypto.spec.PBEKeySpec(passphrase, salt, 310_000, 256)
        val key = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return salt + iv + ct
    }

    private fun decrypt(blob: ByteArray, passphrase: CharArray): String {
        val salt = blob.copyOfRange(0, 16)
        val iv = blob.copyOfRange(16, 28)
        val ct = blob.copyOfRange(28, blob.size)
        val spec = javax.crypto.spec.PBEKeySpec(passphrase, salt, 310_000, 256)
        val key = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    private suspend fun ensureFolder(token: String): String {
        val q = java.net.URLEncoder.encode(
            "name='PassOfflineBackup' and mimeType='application/vnd.google-apps.folder' and trashed=false", "UTF-8")
        val res = khttpGet("https://www.googleapis.com/drive/v3/files?q=$q&fields=files(id)", token)
        val files = JSONObject(res).optJSONArray("files")
        if (files != null && files.length() > 0) return files.getJSONObject(0).getString("id")
        val body = JSONObject().put("name", "PassOfflineBackup")
            .put("mimeType", "application/vnd.google-apps.folder")
        return JSONObject(khttpPost("https://www.googleapis.com/drive/v3/files", token, body)).getString("id")
    }

    suspend fun upload(context: Context, backupFileUri: android.net.Uri, config: DriveConfig, passphrase: CharArray): Result<String> = runCatching {
        val plain = context.contentResolver.openInputStream(backupFileUri)?.use {
            it.readBytes().toString(Charsets.UTF_8)
        } ?: throw IllegalStateException("Cannot read local backup")
        val encrypted = encrypt(plain, passphrase)
        val folderId = ensureFolder(config.accessToken)
        val name = "pass-backup-${System.currentTimeMillis()}.bin"
        val boundary = "passBackupBoundary"
        val meta = JSONObject().put("name", name).put("parents", org.json.JSONArray(listOf(folderId)))
        val head = ("--$boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" +
            meta + "\r\n--$boundary\r\nContent-Type: application/octet-stream\r\n\r\n")
        val payload = (head + Base64Java().encode(encrypted) + "\r\n--$boundary--").toByteArray(Charsets.UTF_8)
        val conn = java.net.URL("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart").openConnection()
            as java.net.HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Authorization", "Bearer ${config.accessToken}")
        conn.setRequestProperty("Content-Type", "multipart/related; boundary=$boundary")
        conn.outputStream.use { it.write(payload) }
        val respCode = conn.responseCode
        if (respCode !in 200..299) throw IllegalStateException("Drive upload failed: $respCode")
        JSONObject(conn.inputStream.bufferedReader().readText()).getString("id")
    }

    suspend fun download(config: DriveConfig, fileId: String, passphrase: CharArray): Result<String> = runCatching {
        val conn = java.net.URL("https://www.googleapis.com/drive/v3/files/$fileId?alt=media").openConnection()
            as java.net.HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("Authorization", "Bearer ${config.accessToken}")
        if (conn.responseCode !in 200..299) throw IllegalStateException("Drive download failed: ${conn.responseCode}")
        val blob = conn.inputStream.readBytes()
        decrypt(blob, passphrase)
    }

    suspend fun list(config: DriveConfig): Result<List<Pair<String, String>>> = runCatching {
        val q = java.net.URLEncoder.encode("name contains 'pass-backup-' and trashed=false", "UTF-8")
        val res = JSONObject(khttpGet("https://www.googleapis.com/drive/v3/files?q=$q&orderBy=modifiedTime desc&fields=files(id,name)", config.accessToken))
        val files = res.optJSONArray("files") ?: return@runCatching emptyList()
        List(files.length()) { i -> files.getJSONObject(i).getString("id") to files.getJSONObject(i).getString("name") }
    }

    private suspend fun khttpGet(url: String, token: String): String {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.setRequestProperty("Authorization", "Bearer $token")
        if (conn.responseCode !in 200..299) throw IllegalStateException("Drive API GET failed: ${conn.responseCode}")
        return conn.inputStream.bufferedReader().readText()
    }

    private suspend fun khttpPost(url: String, token: String, body: JSONObject): String {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Authorization", "Bearer $token")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        if (conn.responseCode !in 200..299) throw IllegalStateException("Drive API POST failed: ${conn.responseCode}")
        return conn.inputStream.bufferedReader().readText()
    }

    private class Base64Java {
        fun encode(bytes: ByteArray): String = java.util.Base64.getUrlEncoder().encodeToString(bytes)
    }
}
