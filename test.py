import os
import datetime
from scapy.all import sniff, IP, TCP, UDP

# Şübhəli fəaliyyətləri log faylına yazmaq üçün funksiya
def log_to_file(message):
    log_file = "exfiltration_alerts.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

# Şübhəli fəaliyyət aşkarlama qaydaları
def detect_exfiltration(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        data_len = len(packet[IP])

        # Böyük paketlər üçün qayda
        if data_len > 1500:  # Məsələn, 1500 baytdan çox paketlər
            alert = f"[ŞÜBHƏLİ] Böyük paket aşkarlandı: {src_ip} -> {dst_ip}, Data uzunluğu: {data_len} bayt"
            print(alert)
            log_to_file(alert)

        # TCP trafikində şübhəli portlar
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if dst_port in [21, 22, 80, 443] and data_len > 1000:  # FTP, SSH, HTTP/HTTPS üzərindən böyük trafiklər
                alert = f"[ŞÜBHƏLİ] TCP port ({dst_port}) ilə şübhəli trafik: {src_ip} -> {dst_ip}, Data uzunluğu: {data_len} bayt"
                print(alert)
                log_to_file(alert)

        # UDP trafikində qeyri-adi DNS sorğuları
        if UDP in packet and (dst_ip.startswith("8.8.8.") or dst_ip.startswith("1.1.1.")):  # Məsələn, Google və ya Cloudflare DNS-lər
            alert = f"[ŞÜBHƏLİ] UDP DNS sorğusu: {src_ip} -> {dst_ip}"
            print(alert)
            log_to_file(alert)

# Şəbəkə interfeysini seçmək (varsayılan olaraq `eth0`)
def main():
    try:
        print("Data Exfiltration aşkarlanması üçün alət işə düşdü...")
        print("Şəbəkə monitorinqi başlayır. Dayandırmaq üçün Ctrl+C basın.")
        sniff(prn=detect_exfiltration, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\nMonitorinq dayandırıldı.")
    except Exception as e:
        print(f"Xəta baş verdi: {str(e)}")
        log_to_file(f"[XƏTA] {str(e)}")

if __name__ == "__main__":
    main()