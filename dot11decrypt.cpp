/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * Author: Matias Fontanini <matias.fontanini@gmail.com>
 * 
 * This small application decrypts WEP/WPA2(AES and TKIP) traffic on
 * the fly and writes the result into a tap interface. 
 * 
 */

// libtins
#include <tins/tins.h>
// linux/POSIX stuff
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
// STL
#include <iostream>
#include <atomic>
#include <algorithm>
#include <tuple>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <memory>

using namespace Tins;

using std::atomic;
using std::lock_guard;
using std::mutex;
using std::unique_ptr;
using std::unique_lock;
using std::condition_variable;
using std::move;
using std::memset;
using std::bind;
using std::cout;
using std::endl;
using std::runtime_error;
using std::invalid_argument;
using std::exception;
using std::thread;
using std::swap;
using std::tuple;
using std::make_tuple;
using std::string;
using std::queue;
using std::get;
using std::vector;

// our running flag
atomic<bool> running;

// unique_fd - just a wrapper over a file descriptor which closes
// the fd in its dtor. non-copyable but movable

class unique_fd {
public:
    static constexpr int invalid_fd = -1;

    unique_fd(int fd = invalid_fd) 
    : fd_(fd) {
        
    }
    
    
    unique_fd(unique_fd &&rhs) 
    : fd_(invalid_fd) {
        *this = move(rhs);
    }
    
    unique_fd& operator=(unique_fd&& rhs) {
        if (fd_ != invalid_fd) {
            ::close(fd_);
        }
        fd_ = invalid_fd;
        swap(fd_, rhs.fd_);
        return *this;
    }
    
    ~unique_fd() {
        if (fd_ != invalid_fd) {
            ::close(fd_);
        }
    }
    
    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;
    
    int operator*() {
        return fd_;
    }
    
    operator bool() const {
        return fd_ != invalid_fd;
    }
private:
    int fd_;
};

// packet_buffer - buffers packets, decrypts them and flushes them into 
// the interface using an auxiliary thread.

class packet_buffer {
public:
    typedef unique_ptr<PDU> unique_pdu;

    packet_buffer(unique_fd fd, Crypto::WPA2Decrypter wpa2d,
                  Crypto::WEPDecrypter wepd)
    : fd_(move(fd)), wpa2_decrypter_(move(wpa2d)), 
    wep_decrypter_(move(wepd)) {
    
    }
    
    packet_buffer(const packet_buffer&) = delete;
    packet_buffer& operator=(const packet_buffer&) = delete;
    
    ~packet_buffer() {
        thread_.join();
    }
    
    void add_packet(unique_pdu pkt) {
        lock_guard<mutex> _(mtx_);
        packet_queue_.push(move(pkt));
        cond_.notify_one();
    }
    
    void stop_running() {
        lock_guard<mutex> _(mtx_);
        cond_.notify_one();
    }
    
    void run() {
        thread_ = thread(&packet_buffer::thread_proc, this);
    }    
private:
    EthernetII make_eth_packet(Dot11Data &dot11) {
        if (dot11.from_ds() && !dot11.to_ds()) {
            return EthernetII(dot11.addr1(), dot11.addr3());
        }
        else if (!dot11.from_ds() && dot11.to_ds()) {
            return EthernetII(dot11.addr3(), dot11.addr2());
        }
        else { 
            return EthernetII(dot11.addr1(), dot11.addr2());
        }
    }
    
    template<typename Decrypter>
    bool try_decrypt(Decrypter &decrypter, PDU &pdu) {
        if (decrypter.decrypt(pdu)) {
            auto &dot11 = pdu.rfind_pdu<Dot11Data>();
            auto &snap = pdu.rfind_pdu<SNAP>();
            // create an EthernetII using the src and dst addrs
            auto pkt = make_eth_packet(dot11);
            // move the inner pdu into the EthernetII to avoid copying
            pkt.inner_pdu(snap.release_inner_pdu());
            auto buffer = pkt.serialize();
            if (write(*fd_, buffer.data(), buffer.size()) == -1) {
                throw runtime_error("Error writing to tap interface");
            }
            // if the decrypter is successfull, then SUCCESS
            return true;
        }
        return false;
    }

    void thread_proc() {
        while (running) {
            unique_pdu pkt;
            // critical section
            {
                unique_lock<mutex> lock(mtx_);
                if (!running) {
                    return;
                }
                if (packet_queue_.empty()) {
                    cond_.wait(lock);
                    // if it's still empty, then we're done
                    if (packet_queue_.empty()) {
                        return;
                    }
                }
                pkt = move(packet_queue_.front());
                packet_queue_.pop();
            }
            // non-critical section
            if (!try_decrypt(wpa2_decrypter_, *pkt.get())) {
                try_decrypt(wep_decrypter_, *pkt.get());
            }
        }
    }

    unique_fd fd_;
    thread thread_;
    mutex mtx_;
    condition_variable cond_;
    queue<unique_pdu> packet_queue_;
    Crypto::WPA2Decrypter wpa2_decrypter_;
    Crypto::WEPDecrypter wep_decrypter_;
};


// traffic_decrypter - decrypts the traffic and forwards it into a
// bufferer

class traffic_decrypter {
public:
    traffic_decrypter(unique_fd fd, Crypto::WPA2Decrypter wpa2d, 
                      Crypto::WEPDecrypter wepd)
    : bufferer_(move(fd), move(wpa2d), move(wepd)) {
        
    }
    
    void decrypt_traffic(Sniffer &sniffer) {
        using std::placeholders::_1;
        
        bufferer_.run();
        sniffer.sniff_loop(bind(&traffic_decrypter::callback, this, _1));
        bufferer_.stop_running();
    }
private:
    bool callback(PDU &pdu) {
        if (pdu.find_pdu<Dot11>() == nullptr && pdu.find_pdu<RadioTap>() == nullptr) {
            throw runtime_error("Expected an 802.11 interface in monitor mode");
        }
        bufferer_.add_packet(packet_buffer::unique_pdu(pdu.clone()));
        return running;
    }

    packet_buffer bufferer_;
};


// if_up - brings the interface up

void if_up(const char *name) {
    int err, fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
   
    if ((err = ioctl(fd, SIOCGIFFLAGS, (void *) &ifr)) < 0) {
        close(fd);
        cout << strerror(errno) << endl;
        throw runtime_error("Failed get flags");
    }
   
    ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
   
    if ((err = ioctl(fd, SIOCSIFFLAGS, (void *) &ifr)) < 0) {
        close(fd);
        cout << strerror(errno) << endl;
        throw runtime_error("Failed to bring the interface up");
    }
}

// create_tap_dev - creates a tap device

tuple<unique_fd, string> create_tap_dev() {
    struct ifreq ifr;
    int err;
    char clonedev[] = "/dev/net/tun";
    unique_fd fd = open(clonedev, O_RDWR);

    if (!fd) {
        throw runtime_error("Failed to open /dev/net/tun");
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;   

    if ((err = ioctl(*fd, TUNSETIFF, (void *) &ifr)) < 0) {
        throw runtime_error("Failed to create tap device");
    }

    return make_tuple(move(fd), ifr.ifr_name);
}

// sig_handler - SIGINT handler, so we can release resources appropriately
void sig_handler(int) {
    if (running) {
        cout << "Stopping the sniffer...\n";
        running = false; 
    }
}


typedef tuple<Crypto::WPA2Decrypter, Crypto::WEPDecrypter> decrypter_tuple;

// Creates a traffic_decrypter and puts it to work
void decrypt_traffic(unique_fd fd, const string &iface, decrypter_tuple tup) {
    Sniffer sniffer(iface, 2500, false);
    traffic_decrypter decrypter(
        move(fd), 
        move(get<0>(tup)), 
        move(get<1>(tup))
    );
    decrypter.decrypt_traffic(sniffer);
}

// parses the arguments and returns a tuple (WPA2Decrypter, WEPDectyper)
// throws if arguments are invalid
decrypter_tuple parse_args(const vector<string> &args) {
    decrypter_tuple tup;
    for (const auto &i : args) {
        if (i.find("wpa:") == 0) {
            auto pos = i.find(':', 4);
            if (pos != string::npos) {
                get<0>(tup).add_ap_data(
                    i.substr(pos + 1), // psk
                    i.substr(4, pos - 4) // ssid
                );
            }
            else {
                throw invalid_argument("Invalid decryption data");
            }
        }
        else if (i.find("wep:") == 0) {
            const auto sz = string("00:00:00:00:00:00").size();
            if (sz + 4 >= i.size()) {
                throw invalid_argument("Invalid decryption data");
            }
            get<1>(tup).add_password(
                i.substr(5, sz), // bssid
                i.substr(5 + sz) // passphrase
            );
        }
        else {
            throw invalid_argument("Expected decription data.");
        }
    }
    return tup;
}

void print_usage(const char *arg0){
    cout << "Usage: " << arg0 << " <interface> DECRYPTION_DATA [DECRYPTION_DATA] [...]\n\n";
    cout << "Where DECRYPTION_DATA can be: \n";
    cout << "\twpa:SSID:PSK - to specify WPA2(AES or TKIP) decryption data.\n";
    cout << "\twep:BSSID:KEY - to specify WEP decryption data.\n\n";
    cout << "Examples:\n";
    cout << "\t" << arg0 << " wlan0 wpa:MyAccessPoint:some_password\n";
    cout << "\t" << arg0 << " mon0 wep:00:01:02:03:04:05:blahbleehh\n";
    exit(1);
}

int main(int argc, char *argv[]) 
{
    if (argc < 3) {
        print_usage(*argv);
    }
    try {
        auto decrypters = parse_args(vector<string>(argv + 2, argv + argc));
        string dev_name;
        unique_fd fd;
        tie(fd, dev_name) = create_tap_dev();
        cout << "Using device: " << dev_name << endl;
        if_up(dev_name.c_str());
        cout << "Device is up.\n";
        signal(SIGINT, sig_handler);
        running = true;
        decrypt_traffic(move(fd), argv[1], move(decrypters));
        cout << "Done\n";
    }
    catch(invalid_argument& ex) {
        cout << "[-] " << ex.what() << endl;
        print_usage(*argv);
    }
    catch(exception& ex) {
        cout << "[-] " << ex.what() << endl;
    }
}
