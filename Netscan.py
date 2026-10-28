import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, conf
from colorama import init, Fore

# Inisialisasi Colorama untuk tampilan terminal berwarna
init(autoreset=True)

# Sembunyikan pesan verbose scapy yang mengganggu
conf.verb = 0

def parse_arguments():
    """Menguraikan argumen dari baris perintah."""
    parser = argparse.ArgumentParser(
        description="Professional IP & Network Scanner menggunakan Python & Scapy"
    )
    parser.add_argument(
        "-t", "--target", 
        required=True, 
        help="Target IP atau CIDR range (contoh: 192.168.1.0/24)"
    )
    parser.add_argument(
        "-w", "--threads", 
        type=int, 
        default=100, 
        help="Jumlah thread maksimum (default: 100)"
    )
    return parser.parse_args()

def scan_ip(ip):
    """Memindai satu alamat IP menggunakan ARP request."""
    try:
        # Membuat paket ARP request untuk IP target
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Mengirim dan menerima paket (timeout 1 detik)
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        if answered_list:
            for sent, received in answered_list:
                return {"ip": received.psrc, "mac": received.hwsrc}
    except Exception as e:
        pass
    return None

def main():
    args = parse_arguments()
    target_range = args.target
    max_threads = args.threads

    print(f"{Fore.CYAN}[*] Memulai pemindaian jaringan pada target: {target_range}")
    print(f"{Fore.CYAN}[*] Menggunakan {max_threads} threads. Mohon tunggu...\n")
    
    start_time = time.time()
    active_hosts = []

    # Karena scapy srp dapat memproses rentang IP secara langsung, 
    # kita juga bisa menggunakan ThreadPool untuk rentang yang lebih besar atau kustom.
    # Di sini kita gunakan fungsi srp bawaan scapy yang sudah sangat optimal untuk subnet /24.
    try:
        # Untuk rentang CIDR (misal /24), srp sangat cepat menangani seluruh subnet sekaligus
        arp_request = ARP(pdst=target_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = srp(broadcast / arp_request, timeout=2, verbose=False)[0]

        for sent, received in answered_list:
            active_hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Pemindaian dibatalkan oleh pengguna.")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Terjadi kesalahan: {e}")
        sys.exit(1)

    end_time = time.time()
    duration = end_time - start_time

    # Menampilkan Hasil dalam Format Tabel yang Rapi
    print("\n" + "=" * 50)
    print(f"{'IP ADDRESS':<20} | {'MAC ADDRESS':<20}")
    print("=" * 50)
    
    if active_hosts:
        for host in active_hosts:
            print(f"{Fore.GREEN}{host['ip']:<20} {Fore.WHITE}| {Fore.YELLOW}{host['mac']:<20}")
    else:
        print(f"{Fore.RED}Tidak ada host yang aktif ditemukan.")
        
    print("=" * 50)
    print(f"{Fore.CYAN}[*] Pemindaian selesai dalam {duration:.2f} detik.")
    print(f"{Fore.CYAN}[*] Total host aktif ditemukan: {len(active_hosts)}")

if __name__ == "__main__":
    main()
