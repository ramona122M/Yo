// app.ts - Script para Deno con efecto ONDA
import { DOMParser } from "https://deno.land/x/deno_dom/deno-dom-wasm.ts";

// Configuración
const CREDENTIAL = "anonymous:d2luOF92M18xNzQ2NzYxMDAzX0O0CIJpR3iX4Q5LhWcfmhU=";
const PASSWORD = "G9CRnQY9mpglgmaO";
const DEVICE_ID = "3287774292218060752";

const TOKEN_URL = "https://eur-janus.gameloft.com/authorize";
const SUBSCRIBE_URL = "https://eur-arion.gameloft.com/chat/channels/mc5_global/subscribe";

const XOR_KEY = "1961151304ELF";

// Patrón de ONDA (espaciados variables)
const WAVE_PATTERN = [0, 2, 5, 0, 1, 4, 2];

// Mensajes base
const MESSAGES = [
  "SENSAID SCAMMER",
  "RAT HACKER KID",
  "SHAMANG THE KING",
  "JAY SHREE RAAM",
  "LODA LEGENS",
  "IF YOU PLAY WITH FIRE",
  "YOU'LL GET BURNED"
];

interface UrlData {
  url: string;
  token: string;
  fed_id: string;
  last_used: number;
  created_at: number;
}

interface UrlStats {
  sent: number;
  failed: number;
}

class AdvancedMultiURLSpam {
  private activeUrls: UrlData[] = [];
  private urlStats: Map<string, UrlStats> = new Map();
  private urlLock = false;
  private active = false;
  private sentCount = 0;
  private failedCount = 0;
  private messageCounter = 0;
  private lastUrlUpdate = 0;
  private lastDisplayUpdate = 0;
  
  private readonly maxUrls = 5;
  private readonly urlUpdateInterval = 120;
  private readonly displayInterval = 5;
  
  constructor(
    private readonly duration: number = 30000,
    private readonly workers: number = 40
  ) {}

  private generarHashXor(nickname: string): string {
    let result = "";
    for (let i = 0; i < nickname.length; i++) {
      const keyChar = XOR_KEY[i % XOR_KEY.length];
      result += String.fromCharCode(nickname.charCodeAt(i) ^ keyChar.charCodeAt(0));
    }
    return result;
  }

  private generarNickname(): string {
    const bases = ["SENSAID", "SCAMMER", "RAT", "SHAMANG", "KING"];
    return bases[Math.floor(Math.random() * bases.length)] + 
           Math.floor(Math.random() * 999).toString();
  }

  private generarMensajeOnda(): string {
    const espaciado = WAVE_PATTERN[this.messageCounter % WAVE_PATTERN.length];
    this.messageCounter++;
    const mensajeBase = MESSAGES[Math.floor(Math.random() * MESSAGES.length)];
    return " ".repeat(espaciado) + mensajeBase;
  }

  private async obtenerNuevaUrl(): Promise<UrlData | null> {
    try {
      const tokenPayload = new URLSearchParams({
        client_id: "1875:55979:5.9.2a:windows:windows",
        username: CREDENTIAL,
        password: PASSWORD,
        scope: "alert auth chat leaderboard_ro lobby message session social",
        device_id: DEVICE_ID,
        for_credential_type: "anonymous",
        device_country: "US",
        device_language: "id",
        device_model: "Pixel",
        device_resolution: "1532x700"
      });

      const tokenResponse = await fetch(TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenPayload
      });

      if (!tokenResponse.ok) return null;
      
      const tokenData = await tokenResponse.json();
      const token = tokenData.access_token;
      const fed_id = tokenData.fed_id;
      
      if (!token || !fed_id) return null;

      const chatPayload = new URLSearchParams({
        language: "en",
        access_token: token
      });

      const chatResponse = await fetch(SUBSCRIBE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: chatPayload
      });

      if (!chatResponse.ok) return null;
      
      const chatData = await chatResponse.json();
      const chatUrl = chatData.cmd_url;
      
      if (!chatUrl) return null;

      const urlData: UrlData = {
        url: chatUrl,
        token,
        fed_id,
        last_used: Date.now() / 1000,
        created_at: Date.now() / 1000
      };

      while (this.urlLock) await new Promise(resolve => setTimeout(resolve, 10));
      this.urlLock = true;
      
      if (this.activeUrls.length >= this.maxUrls) {
        const oldUrl = this.activeUrls.shift();
        if (oldUrl) this.urlStats.delete(oldUrl.url);
      }
      
      this.urlStats.set(chatUrl, { sent: 0, failed: 0 });
      this.activeUrls.push(urlData);
      
      this.urlLock = false;
      
      console.log(`✅ Nueva URL obtenida: ${chatUrl.substring(0, 50)}...`);
      return urlData;

    } catch (error) {
      return null;
    }
  }

  private obtenerUrlActiva(): UrlData | null {
    while (this.urlLock) return null;
    
    this.urlLock = true;
    
    if (this.activeUrls.length === 0) {
      this.urlLock = false;
      return null;
    }
    
    this.activeUrls.sort((a, b) => a.last_used - b.last_used);
    
    const urlData = this.activeUrls[0];
    urlData.last_used = Date.now() / 1000;
    
    this.urlLock = false;
    return urlData;
  }

  private async enviarMensaje(): Promise<void> {
    if (!this.active) return;

    try {
      const urlData = this.obtenerUrlActiva();
      if (!urlData) {
        this.failedCount++;
        return;
      }

      const nickname = this.generarNickname();
      const mensaje = this.generarMensajeOnda();
      const hashXor = this.generarHashXor(nickname);
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const urlObj = new URL(urlData.url);
      const hostChat = urlObj.hostname;

      const payload = new URLSearchParams({
        _killSignColor: "16777215",
        _messageType: "-1",
        _fedId: `fed_id:${urlData.fed_id}`,
        _senderTimestamp: timestamp,
        _senderName: nickname,
        _anonId: CREDENTIAL,
        _killSign: "gameloft",
        _: hashXor,
        msg: mensaje,
        user: JSON.stringify({ nickname }),
        access_token: urlData.token
      });

      const response = await fetch(urlData.url, {
        method: "POST",
        headers: {
          "Host": hostChat,
          "User-Agent": "ChatLibv2",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: payload
      });

      if (response.ok) {
        this.sentCount++;
        const stats = this.urlStats.get(urlData.url);
        if (stats) stats.sent++;
        console.log(`📨 ${mensaje}`);
      } else {
        this.failedCount++;
        const stats = this.urlStats.get(urlData.url);
        if (stats) stats.failed++;
      }

    } catch (error) {
      this.failedCount++;
    }
  }

  private mostrarEstadisticas(elapsedTime: number, totalTime: number): void {
    const now = Date.now() / 1000;
    if (now - this.lastDisplayUpdate >= this.displayInterval) {
      this.lastDisplayUpdate = now;
      
      const speed = this.sentCount / elapsedTime;
      const remaining = totalTime - elapsedTime;
      
      console.log(`\r⏱️ ${Math.floor(elapsedTime)}s | ✅ ${this.sentCount} | ❌ ${this.failedCount} | 🚀 ${speed.toFixed(1)}/s | ⏳ ${Math.floor(remaining)}s`);
    }
  }

  private async urlMaintenanceWorker(): Promise<void> {
    while (this.active) {
      const now = Date.now() / 1000;
      
      if (now - this.lastUrlUpdate >= this.urlUpdateInterval) {
        this.lastUrlUpdate = now;
        await this.obtenerNuevaUrl();
      }
      
      if (this.activeUrls.length < 3) {
        await this.obtenerNuevaUrl();
      }
      
      await new Promise(resolve => setTimeout(resolve, 10000));
    }
  }

  public async start(): Promise<void> {
    console.log("=".repeat(60));
    console.log("🚀 INICIANDO SPAM CON EFECTO ONDA EN DENO");
    console.log("=".repeat(60));
    console.log(`🔑 Credencial: ${CREDENTIAL.substring(0, 30)}...`);
    console.log(`📱 Device ID: ${DEVICE_ID}`);
    console.log(`⏱️  Duración: ${this.duration} segundos (${(this.duration/3600).toFixed(1)} horas)`);
    console.log(`👷 Workers: ${this.workers}`);
    console.log(`🌐 URLs simultáneas: Máximo ${this.maxUrls}`);
    console.log("\n🌊 PATRÓN DE ONDA:");
    console.log("   Mensaje 1: 'hola'");
    console.log("   Mensaje 2: '  hola'");
    console.log("   Mensaje 3: '        hola'");
    console.log("   Mensaje 4: 'hola'");
    console.log("   Mensaje 5: ' hola'");
    console.log("   Mensaje 6: '       hola'");
    console.log("   Mensaje 7: '   hola'");
    console.log("=".repeat(60));
    console.log("Iniciando en 3 segundos...");
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    this.active = true;
    this.sentCount = 0;
    this.failedCount = 0;
    this.messageCounter = 0;
    
    console.log("\n🔍 Obteniendo URLs iniciales...");
    for (let i = 0; i < 3; i++) {
      const urlData = await this.obtenerNuevaUrl();
      console.log(urlData ? `  ✅ URL ${i+1} obtenida` : `  ❌ URL ${i+1}: Falló`);
    }
    
    if (this.activeUrls.length === 0) {
      console.log("\n❌ ERROR: No se pudo obtener ninguna URL");
      return;
    }
    
    this.urlMaintenanceWorker();
    
    console.log(`\n✅ ${this.workers} workers iniciados`);
    console.log("📊 Enviando mensajes con EFECTO ONDA...\n");
    
    const startTime = Date.now() / 1000;
    const workers_promises = [];
    
    for (let i = 0; i < this.workers; i++) {
      workers_promises.push((async () => {
        while (this.active && (Date.now() / 1000 - startTime) < this.duration) {
          await this.enviarMensaje();
          await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
        }
      })());
    }
    
    while (this.active && (Date.now() / 1000 - startTime) < this.duration) {
      const elapsedTime = Date.now() / 1000 - startTime;
      this.mostrarEstadisticas(elapsedTime, this.duration);
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    this.active = false;
    await Promise.all(workers_promises);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const totalTime = Date.now() / 1000 - startTime;
    const totalAttempts = this.sentCount + this.failedCount;
    const successRate = totalAttempts > 0 ? (this.sentCount / totalAttempts * 100) : 0;
    const speed = this.sentCount / totalTime;
    
    console.log("\n\n" + "=".repeat(80));
    console.log("🎉 SPAM CON EFECTO ONDA COMPLETADO");
    console.log(`📊 RESUMEN: ✅ ${this.sentCount} | ❌ ${this.failedCount} | 🎯 ${successRate.toFixed(1)}%`);
    console.log(`🚀 Velocidad: ${speed.toFixed(2)} msg/s | ⏱️  Tiempo: ${totalTime.toFixed(1)}s`);
    console.log("=".repeat(80));
  }
}

// Punto de entrada
if (import.meta.main) {
  console.log("=".repeat(60));
  console.log("🚀 INICIANDO SCRIPT EN DENO 2.6.8");
  console.log("🌊 Efecto ONDA activado");
  console.log("=".repeat(60));
  
  const spam = new AdvancedMultiURLSpam(30000, 40);
  await spam.start();
}
