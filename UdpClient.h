#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

class UdpClient
{
    using udp = boost::asio::ip::udp;
public:
    static constexpr std::uint8_t MAGIC = 0xA7;
    static constexpr std::uint8_t C2S_BIND = 0x01, C2S_INPUT = 0x02;
    static constexpr std::uint8_t S2C_BIND_OK = 0x81, S2C_DATA = 0x82;
    static constexpr std::size_t HEADER = 10, TAG = 8, MAX_DATAGRAM = 1200, CMD_LEN = 10, MAX_CMDS = 8;

    using Key = std::array<std::uint8_t, 16>;
    using Cmd = std::array<std::uint8_t, CMD_LEN>;        // u32 seq, u8 flags, u8 nums, i16 aimX, i16 aimY
    using Handler = std::function<void(const std::uint8_t*, std::size_t)>;

    UdpClient(boost::asio::io_context& io, Handler on_data)
        : socket_(io), timer_(io), on_data_(std::move(on_data)) {}

    bool bound() const { return active_ && bound_; }

    void start(const std::string& host, std::uint16_t port, std::uint32_t sid, const Key& key)
    {
        stop();
        boost::system::error_code ec;
        udp::resolver res(socket_.get_executor());
        auto results = res.resolve(udp::v4(), host, std::to_string(port), ec);   // сервер слушает только IPv4
        if (ec || results.begin() == results.end()) { std::cerr << "[udp] resolve failed\n"; return; }
        server_ = results.begin()->endpoint();

        socket_.open(udp::v4(), ec);
        if (ec) return;

        sid_ = sid; key_ = key; send_seq_ = 0; window_ = Window{};
        bound_ = false; tries_ = 0; active_ = true;
        const auto e = ++epoch_;
        receive(e);
        arm_bind(e);
    }

    void stop()
    {
        active_ = false; bound_ = false;
        ++epoch_;
        boost::system::error_code ec;
        timer_.cancel();
        socket_.close(ec);
    }

    // ѕоследние команды, старые первыми (избыточность вместо повторной отправки)
    void send_input(const std::deque<Cmd>& hist)
    {
        if (!bound() || hist.empty()) return;
        std::uint8_t buf[1 + MAX_CMDS * CMD_LEN];
        const std::size_t n = std::min(hist.size(), MAX_CMDS);
        buf[0] = static_cast<std::uint8_t>(n);
        for (std::size_t i = 0; i < n; ++i)
            std::memcpy(buf + 1 + i * CMD_LEN, hist[hist.size() - n + i].data(), CMD_LEN);
        send(C2S_INPUT, buf, 1 + n * CMD_LEN);
    }

private:
    struct Window            // защита от повторов, как на сервере
    {
        std::uint32_t highest = 0; std::uint64_t bits = 0; bool init = false;
        bool accept(std::uint32_t s)
        {
            if (!init) { init = true; highest = s; bits = 1; return true; }
            if (s > highest) { auto sh = s - highest; bits = sh >= 64 ? 0 : (bits << sh); bits |= 1; highest = s; return true; }
            auto d = highest - s;
            if (d >= 64 || (bits & (1ull << d))) return false;
            bits |= 1ull << d; return true;
        }
    };

    void arm_bind(std::uint32_t e)
    {
        if (!active_ || bound_ || e != epoch_) return;
        if (++tries_ > 20) { std::cerr << "[udp] bind failed, staying on TCP\n"; return; }
        send(C2S_BIND, nullptr, 0);
        timer_.expires_after(std::chrono::milliseconds(500));
        timer_.async_wait([this, e](const boost::system::error_code& ec)
            { if (!ec && e == epoch_) arm_bind(e); });
    }

    void receive(std::uint32_t e)
    {
        socket_.async_receive_from(boost::asio::buffer(buf_), from_,
            [this, e](const boost::system::error_code& ec, std::size_t n)
            {
                if (e != epoch_ || ec == boost::asio::error::operation_aborted ||
                    ec == boost::asio::error::bad_descriptor) return;
                if (!ec) handle(n);
                receive(e);            // ICMP-ошибки Windows не должны останавливать приЄм
            });
    }

    void handle(std::size_t n)
    {
        if (from_ != server_) return;
        if (n < HEADER + TAG || n > MAX_DATAGRAM || buf_[0] != MAGIC) return;
        if (rd32(&buf_[1]) != sid_) return;
        if (!verify(buf_.data(), n)) return;
        if (!window_.accept(rd32(&buf_[5]))) return;

        const std::uint8_t type = buf_[9];
        const std::uint8_t* p = buf_.data() + HEADER;
        const std::size_t len = n - HEADER - TAG;

        if (type == S2C_BIND_OK)
        {
            std::cout << "[udp] bound" << std::endl;   // <-- лог
            bound_ = true;
            timer_.cancel();
        }
        else if (type == S2C_DATA && on_data_) on_data_(p, len);
    }

    void send(std::uint8_t type, const std::uint8_t* payload, std::size_t len)
    {
        std::array<std::uint8_t, MAX_DATAGRAM> out;
        std::size_t n = 0;
        out[n++] = MAGIC;
        wr32(&out[n], sid_); n += 4;
        wr32(&out[n], ++send_seq_); n += 4;
        out[n++] = type;
        if (len) { std::memcpy(&out[n], payload, len); n += len; }
        sign(out.data(), n, &out[n]); n += TAG;
        boost::system::error_code ec;
        socket_.send_to(boost::asio::buffer(out.data(), n), server_, 0, ec);   // потери допустимы
    }

    void sign(const std::uint8_t* d, std::size_t len, std::uint8_t* tag) const
    {
        unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
        HMAC(EVP_sha256(), key_.data(), (int)key_.size(), d, len, md, &mdlen);
        std::memcpy(tag, md, TAG);
    }
    bool verify(const std::uint8_t* d, std::size_t n) const
    {
        std::uint8_t exp[TAG];
        sign(d, n - TAG, exp);
        return CRYPTO_memcmp(exp, d + n - TAG, TAG) == 0;
    }
    static std::uint32_t rd32(const std::uint8_t* p)
    {
        return p[0] | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
    }
    static void wr32(std::uint8_t* p, std::uint32_t v)
    {
        p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
    }

    udp::socket socket_;
    boost::asio::steady_timer timer_;
    Handler on_data_;
    udp::endpoint server_, from_;
    std::array<std::uint8_t, 1500> buf_{};
    std::uint32_t sid_ = 0, send_seq_ = 0, epoch_ = 0;
    Key key_{};
    Window window_;
    bool active_ = false, bound_ = false;
    int tries_ = 0;
};