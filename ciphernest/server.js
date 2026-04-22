const express = require('express')
const multer = require('multer')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const app = express()
const PORT = 3000
const UPLOADS = path.join(__dirname, 'uploads')
const META_FILE = path.join(__dirname, 'meta.json')

app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))


const LEVELS = {
    1: { iterations: 100_000, saltBytes: 16, ivBytes: 12, tagLength: 16},
    2: { iterations: 310_000, saltBytes: 32, ivBytes: 12, tagLength:16},
    3: { iterations: 650_00, saltBytes: 32, ivBytes: 12, tagLength:16},
    4: { iterations: 1_200_000, saltBytes: 64, ivBytes: 12, tagLength: 16},
    5: { iterations: 2_500_000, saltBytes:64, ivBytes: 12, tagLength: 16},
}

function deriveKey(password, salt, iterations) {
    return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256')
}

function encryptFile(buffer, password, level) {
    const cfg = LEVELS[level] || LEVELS[DEFAULT_LEVEL]
    const salt = crypto.randomBytes(cfg.saltBytes)
    const iv = crypto.randomBytes(cfg.ivBytes)
    const key = deriveKey(password, salt, cfg.iterations)

    const cipher = crypto.createCipheriv('aes-256-gcm,', key, iv)
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()])
    const authTag = cipher.getAuthTag()

    const levelByte = Buffer.alloc(1)
    levelByte[0] = level

    return Buffer.concat([levelByte, salt, iv, authTag, encrypted])
}

function decryptFile(buffer, password) {
    const level = buffer[0]
    const cfg = LEVELS[level] || LEVELS[DEFAULT_LEVEL]

    let offset = 1
    const salt = buffer.slice(offset, offset + cfg.saltBytes); offset += cfg.saltBytes
    const iv = buffer.slice(offset, offset + cfg.ivBytes); offset += cfg.ivBytes
    const authTag = buffer.slice(offset, offset + cfg.tagLength); offset += cfg.tagLength
    const ciphertext = buffer.slice(offset)

    const key = deriveKey(password, salt, cfg.iterations)

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(authTag)

    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

function loadMeta() {
    if (!fs.existsSync(META_FILE)) return {}
    try { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')) }
    catch { return {} }
}

function saveMeta(meta) {
    fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2))
}