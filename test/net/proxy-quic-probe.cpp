// SPDX-License-Identifier: GPL-2.0-or-later
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/ton_api.hpp"
#include "keys/keys.hpp"
#include "quic/quic-server.h"
#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/misc.h"
#include "tl-utils/common-utils.hpp"

class QuicHttpProbe : public td::actor::Actor {
 public:
  QuicHttpProbe(td::IPAddress remote, std::optional<ton::adnl::AdnlNodeIdShort> identity, std::string host)
      : remote_(remote), identity_(identity), host_(std::move(host)) {}

  class Callback : public ton::quic::QuicServer::Callback {
   public:
    explicit Callback(td::actor::ActorId<QuicHttpProbe> owner) : owner_(owner) {}
    td::Status on_connected(ton::quic::QuicConnectionId cid, td::SecureString, td::SecureString peer,
                            bool is_outbound) override {
      if (!is_outbound) {
        return td::Status::Error("probe accepts only its outbound connection");
      }
      td::actor::send_closure(owner_, &QuicHttpProbe::connected, cid, std::move(peer));
      return td::Status::OK();
    }
    td::Status on_stream(ton::quic::QuicConnectionId, ton::quic::QuicStreamID sid, td::BufferSlice data,
                         bool is_end) override {
      td::actor::send_closure(owner_, &QuicHttpProbe::data, sid, std::move(data), is_end);
      return td::Status::OK();
    }
    void on_stream_closed(ton::quic::QuicConnectionId, ton::quic::StreamCloseEvent event) override {
      td::actor::send_closure(owner_, &QuicHttpProbe::closed_stream, event.sid);
    }
    void on_closed(ton::quic::QuicConnectionId) override {
      td::actor::send_closure(owner_, &QuicHttpProbe::finish, 0, false, false, true);
    }
    void set_peer_mtu_callback(
        std::function<td::uint64(ton::adnl::AdnlNodeIdShort, ton::adnl::AdnlNodeIdShort)>) override {}
   private:
    td::actor::ActorId<QuicHttpProbe> owner_;
  };

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(5.0);
    auto key = td::Ed25519::generate_private_key().move_as_ok();
    auto local_id = ton::adnl::AdnlNodeIdFull{
        ton::PublicKey{ton::pubkeys::Ed25519{key.get_public_key().move_as_ok()}}}.compute_short_id();
    auto identity = ton::quic::ServerIdentity{.local_id = local_id,
                                               .key = td::Ed25519::PrivateKey{key.as_octet_string()}};
    server_ = ton::quic::QuicServer::create(0, std::make_unique<Callback>(actor_id(this)), 16 << 10,
                                            std::move(identity), "ton", "127.0.0.1").move_as_ok();
    auto sni = identity_ ? ton::quic::ServerIdentity::sni(*identity_) : std::string{};
    td::actor::send_closure(server_, &ton::quic::QuicServer::connect, remote_.get_ip_host(), remote_.get_port(),
                            std::move(key), td::Slice("ton"), std::move(sni));
  }

  void connected(ton::quic::QuicConnectionId cid, td::SecureString key) {
    if (key.size() != 32) {
      finish(0, false, false, true);
      return;
    }
    td::Bits256 bits;
    bits.as_slice().copy_from(key.as_slice());
    auto peer = ton::adnl::AdnlNodeIdFull{ton::PublicKey{ton::pubkeys::Ed25519{bits}}}.compute_short_id();
    peer_id_ = peer.bits256_value().to_hex();
    if (identity_ && *identity_ != peer) {
      finish(0, false, false, true);
      return;
    }
    request(cid).start().detach("HTTP identity probe");
  }

  td::actor::Task<> request(ton::quic::QuicConnectionId cid) {
    td::Bits256 id;
    td::Random::secure_bytes(id.as_slice());
    std::vector<ton::tl_object_ptr<ton::ton_api::http_header>> headers;
    headers.push_back(ton::create_tl_object<ton::ton_api::http_header>("Host", host_));
    auto http = ton::create_serialize_tl_object<ton::ton_api::http_request>(
        id, "GET", "/identity-check/small", "HTTP/1.1", std::move(headers));
    auto wire = ton::create_serialize_tl_object<ton::ton_api::quic_query>(std::move(http));
    auto result = co_await td::actor::ask(server_, &ton::quic::QuicServer::send_stream, cid,
        ton::quic::StreamOptions{.max_size = 16 << 10}, std::move(wire), true).wrap();
    if (result.is_error()) {
      finish(0, false, false, true);
    } else {
      sid_ = result.move_as_ok();
    }
    co_return td::Unit{};
  }

  void data(ton::quic::QuicStreamID sid, td::BufferSlice part, bool is_end) {
    if (done_ || !sid_ || sid != *sid_) {
      return;
    }
    if (wire_.size() + part.size() > 16 * 1024) {
      finish(0, false, false, true);
      return;
    }
    wire_.append(part.as_slice().str());
    if (!is_end) {
      return;
    }
    auto answer = ton::fetch_tl_object<ton::ton_api::quic_answer>(td::BufferSlice(wire_), true);
    if (answer.is_error()) {
      finish(0, false, false, true);
      return;
    }
    auto response = ton::fetch_tl_object<ton::ton_api::http_response>(answer.move_as_ok()->data_, true);
    if (response.is_error()) {
      finish(0, false, false, true);
      return;
    }
    finish(response.move_as_ok()->status_code_, false, false, false);
  }

  void closed_stream(ton::quic::QuicStreamID sid) {
    if (sid_ && sid == *sid_) {
      finish(0, true, false, false);
    }
  }
  void alarm() override { finish(0, false, true, false); }
  void finish(int status, bool stream_closed, bool timed_out, bool invalid_response) {
    if (done_) {
      return;
    }
    done_ = true;
    std::cout << "{\"peer_id\":\"" << peer_id_ << "\",\"http_status\":"
              << (status ? std::to_string(status) : "null")
              << ",\"stream_closed\":" << (stream_closed ? "true" : "false")
              << ",\"timed_out\":" << (timed_out ? "true" : "false")
              << ",\"invalid_response\":" << (invalid_response ? "true" : "false") << "}" << std::endl;
    td::actor::SchedulerContext::get().stop();
    stop();
  }

 private:
  td::IPAddress remote_;
  std::optional<ton::adnl::AdnlNodeIdShort> identity_;
  std::string host_, peer_id_, wire_;
  std::optional<ton::quic::QuicStreamID> sid_;
  td::actor::ActorOwn<ton::quic::QuicServer> server_;
  bool done_ = false;
};

int main(int argc, char **argv) {
  if (argc != 4) {
    return 2;
  }
  td::IPAddress remote;
  remote.init_host_port(td::CSlice(argv[1])).ensure();
  std::optional<ton::adnl::AdnlNodeIdShort> identity;
  if (std::string(argv[2]) != "-") {
    auto raw = td::hex_decode(td::Slice(argv[2])).move_as_ok();
    if (raw.size() != 32) {
      return 2;
    }
    td::Bits256 bits;
    bits.as_slice().copy_from(raw);
    identity = ton::adnl::AdnlNodeIdShort{bits};
  }
  td::actor::Scheduler scheduler({1});
  scheduler.run_in_context([&] {
    td::actor::create_actor<QuicHttpProbe>("probe", remote, identity, std::string(argv[3])).release();
  });
  scheduler.run();
}
