<template>
  <div>
    <div class="page-header">
      <h2>🔧 工具箱</h2>
      <p>编码解码、加密解密、数据格式化等常用工具</p>
    </div>

    <el-tabs v-model="activeTab" type="border-card">
      <!-- Encoding -->
      <el-tab-pane label="编码解码" name="encode">
        <div style="padding:8px">
          <el-radio-group v-model="encodeMode" style="margin-bottom:16px">
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="url">URL</el-radio-button>
            <el-radio-button value="hex">Hex</el-radio-button>
            <el-radio-button value="html">HTML</el-radio-button>
            <el-radio-button value="unicode">Unicode</el-radio-button>
            <el-radio-button value="base32">Base32</el-radio-button>
          </el-radio-group>
          <el-input v-model="encodeInput" type="textarea" :rows="4" placeholder="输入文本" style="margin-bottom:12px" />
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <el-button type="primary" @click="encode">编码 →</el-button>
            <el-button @click="decode">← 解码</el-button>
            <el-button text @click="[encodeInput, encodeOutput] = [encodeOutput, encodeInput]">交换</el-button>
            <el-button text @click="encodeOutput = ''">清空</el-button>
          </div>
          <el-input v-model="encodeOutput" type="textarea" :rows="4" placeholder="结果" readonly />
        </div>
      </el-tab-pane>

      <!-- Hash -->
      <el-tab-pane label="哈希计算" name="hash">
        <div style="padding:8px">
          <el-input v-model="hashInput" type="textarea" :rows="3" placeholder="输入文本" style="margin-bottom:12px" />
          <el-button type="primary" @click="calcHash" style="margin-bottom:12px">计算</el-button>
          <div v-if="hashResult">
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="MD5"><code style="user-select:all">{{ hashResult.md5 }}</code></el-descriptions-item>
              <el-descriptions-item label="SHA1"><code style="user-select:all">{{ hashResult.sha1 }}</code></el-descriptions-item>
              <el-descriptions-item label="SHA256"><code style="user-select:all">{{ hashResult.sha256 }}</code></el-descriptions-item>
              <el-descriptions-item label="SHA512"><code style="user-select:all">{{ hashResult.sha512 }}</code></el-descriptions-item>
            </el-descriptions>
          </div>
        </div>
      </el-tab-pane>

      <!-- Crypto -->
      <el-tab-pane label="加密解密" name="crypto">
        <div style="padding:8px">
          <el-radio-group v-model="cryptoMode" style="margin-bottom:16px">
            <el-radio-button value="aes">AES</el-radio-button>
            <el-radio-button value="des">DES</el-radio-button>
          </el-radio-group>
          <el-input v-model="cryptoInput" type="textarea" :rows="3" placeholder="输入文本" style="margin-bottom:12px" />
          <el-input v-model="cryptoKey" placeholder="密钥" style="margin-bottom:12px" />
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <el-button type="primary" @click="encrypt">加密</el-button>
            <el-button @click="decrypt">解密</el-button>
          </div>
          <el-input v-model="cryptoOutput" type="textarea" :rows="3" placeholder="结果" readonly />
        </div>
      </el-tab-pane>

      <!-- JSON -->
      <el-tab-pane label="JSON格式化" name="json">
        <div style="padding:8px">
          <el-input v-model="jsonInput" type="textarea" :rows="8" placeholder="输入JSON" style="margin-bottom:12px" />
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <el-button type="primary" @click="formatJson">格式化</el-button>
            <el-button @click="compressJson">压缩</el-button>
          </div>
          <el-input v-model="jsonOutput" type="textarea" :rows="8" placeholder="结果" readonly />
        </div>
      </el-tab-pane>

      <!-- IP Calculator -->
      <el-tab-pane label="IP计算器" name="ipcalc">
        <div style="padding:8px">
          <el-input v-model="ipcalcInput" placeholder="输入CIDR，如 192.168.1.0/24" style="margin-bottom:12px" />
          <el-button type="primary" @click="calcIP" style="margin-bottom:12px">计算</el-button>
          <div v-if="ipcalcResult">
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="网络地址">{{ ipcalcResult.network }}</el-descriptions-item>
              <el-descriptions-item label="广播地址">{{ ipcalcResult.broadcast }}</el-descriptions-item>
              <el-descriptions-item label="子网掩码">{{ ipcalcResult.subnet_mask }}</el-descriptions-item>
              <el-descriptions-item label="CIDR">{{ ipcalcResult.cidr }}</el-descriptions-item>
              <el-descriptions-item label="主机范围">{{ ipcalcResult.host_min }} - {{ ipcalcResult.host_max }}</el-descriptions-item>
              <el-descriptions-item label="可用主机数">{{ ipcalcResult.usable_hosts }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </div>
      </el-tab-pane>

      <!-- JWT -->
      <el-tab-pane label="JWT解析" name="jwt">
        <div style="padding:8px">
          <el-input v-model="jwtInput" type="textarea" :rows="3" placeholder="粘贴JWT Token" style="margin-bottom:12px" />
          <el-button type="primary" @click="parseJwt" style="margin-bottom:12px">解析</el-button>
          <div v-if="jwtResult">
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="算法">{{ jwtResult.algorithm }}</el-descriptions-item>
              <el-descriptions-item label="Header"><pre style="margin:0;font-size:12px">{{ formatJsonStr(jwtResult.header) }}</pre></el-descriptions-item>
              <el-descriptions-item label="Payload"><pre style="margin:0;font-size:12px">{{ formatJsonStr(jwtResult.payload) }}</pre></el-descriptions-item>
              <el-descriptions-item label="Signature"><code style="user-select:all;font-size:11px">{{ jwtResult.signature }}</code></el-descriptions-item>
            </el-descriptions>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { EncodeText, DecodeText, HashText, AESEncrypt, AESDecrypt, DESEncrypt, DESDecrypt, FormatJSON, CompressJSON, CalculateCIDR, ParseJWT } from '../wailsjs/go/app/App'

const activeTab = ref('encode')

// Encode
const encodeMode = ref('base64')
const encodeInput = ref('')
const encodeOutput = ref('')
async function encode() { try { const r = await EncodeText(encodeInput.value, encodeMode.value); encodeOutput.value = r.output } catch (e) { encodeOutput.value = 'Error: ' + e.message } }
async function decode() { try { const r = await DecodeText(encodeInput.value, encodeMode.value); encodeOutput.value = r.output } catch (e) { encodeOutput.value = 'Error: ' + e.message } }

// Hash
const hashInput = ref('')
const hashResult = ref(null)
async function calcHash() { try { hashResult.value = await HashText(hashInput.value) } catch (e) { console.error(e) } }

// Crypto
const cryptoMode = ref('aes')
const cryptoInput = ref('')
const cryptoKey = ref('')
const cryptoOutput = ref('')
async function encrypt() {
  try {
    if (cryptoMode.value === 'aes') cryptoOutput.value = await AESEncrypt(cryptoInput.value, cryptoKey.value)
    else cryptoOutput.value = await DESEncrypt(cryptoInput.value, cryptoKey.value)
  } catch (e) { cryptoOutput.value = 'Error: ' + e.message }
}
async function decrypt() {
  try {
    if (cryptoMode.value === 'aes') cryptoOutput.value = await AESDecrypt(cryptoInput.value, cryptoKey.value)
    else cryptoOutput.value = await DESDecrypt(cryptoInput.value, cryptoKey.value)
  } catch (e) { cryptoOutput.value = 'Error: ' + e.message }
}

// JSON
const jsonInput = ref('')
const jsonOutput = ref('')
async function formatJson() { try { jsonOutput.value = await FormatJSON(jsonInput.value) } catch (e) { jsonOutput.value = 'Error: ' + e.message } }
async function compressJson() { try { jsonOutput.value = await CompressJSON(jsonInput.value) } catch (e) { jsonOutput.value = 'Error: ' + e.message } }

// IP Calculator
const ipcalcInput = ref('')
const ipcalcResult = ref(null)
async function calcIP() { try { ipcalcResult.value = await CalculateCIDR(ipcalcInput.value) } catch (e) { console.error(e) } }

// JWT
const jwtInput = ref('')
const jwtResult = ref(null)
async function parseJwt() { try { jwtResult.value = await ParseJWT(jwtInput.value) } catch (e) { console.error(e) } }

function formatJsonStr(s) { try { return JSON.stringify(JSON.parse(s), null, 2) } catch { return s } }
</script>
