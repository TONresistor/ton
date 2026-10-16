#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-peer-table.h"
#include "auto/tl/ton_api_json.h"
#include "dht/dht.h"
#include "keyring/keyring.h"
#include "td/actor/coro_utils.h"
#include "td/utils/filesystem.h"
#include "td/utils/OptionParser.h"
#include "td/utils/port/signals.h"

class DhtFixture : public td::actor::Actor {
 public:
  DhtFixture(std::string global, std::string local, std::string root)
      : global_(std::move(global)), local_(std::move(local)), root_(std::move(root)) {}
  void start_up() override { initialize().start().detach("test DHT initialization"); }
 private:
  std::string global_, local_, root_;
  td::actor::ActorOwn<ton::keyring::Keyring> keyring_;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> network_;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl_;
  td::actor::ActorOwn<ton::dht::Dht> dht_;
  td::actor::Task<> initialize() {
    auto global_data = td::read_file(global_).move_as_ok();
    auto global_json = td::json_decode(global_data.as_slice()).move_as_ok();
    ton::ton_api::config_global global;
    ton::ton_api::from_json(global, global_json.get_object()).ensure();
    auto config = ton::dht::Dht::create_global_config(std::move(global.dht_)).move_as_ok();
    auto local_data = td::read_file(local_).move_as_ok();
    auto local_json = td::json_decode(local_data.as_slice()).move_as_ok();
    ton::ton_api::engine_validator_config local;
    ton::ton_api::from_json(local, local_json.get_object()).ensure();
    CHECK(!local.adnl_.empty() && !local.addrs_.empty());
    CHECK(local.addrs_[0]->get_id() == ton::ton_api::engine_addr::ID);
    auto &address = static_cast<ton::ton_api::engine_addr &>(*local.addrs_[0]);
    td::IPAddress ip;
    ip.init_ipv4_port("127.0.0.1", address.port_).ensure();
    auto id = ton::adnl::AdnlNodeIdShort(local.adnl_[0]->id_);
    keyring_ = ton::keyring::Keyring::create(root_ + "/keyring");
    auto public_key = co_await td::actor::ask(keyring_, &ton::keyring::Keyring::get_public_key, id.pubkey_hash());
    network_ = ton::adnl::AdnlNetworkManager::create();
    adnl_ = ton::adnl::Adnl::create(root_, keyring_.get());
    td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_network_manager, network_.get());
    ton::adnl::AdnlCategoryMask mask;
    mask[0] = true;
    td::actor::send_closure(network_, &ton::adnl::AdnlNetworkManager::add_self_addr, ip, mask, 0);
    ton::adnl::AdnlAddressList list;
    list.add_udp_adnl_address(ip).ensure();
    list.set_version(static_cast<td::int32>(td::Clocks::system()));
    list.set_reinit_date(ton::adnl::Adnl::adnl_start_time());
    td::actor::send_closure(adnl_, &ton::adnl::Adnl::add_id, ton::adnl::AdnlNodeIdFull(public_key), list, td::uint8(0));
    dht_ = ton::dht::Dht::create(id, "", config, keyring_.get(), adnl_.get()).move_as_ok();
    td::actor::send_closure(adnl_, &ton::adnl::Adnl::register_dht_node, dht_.get());
    co_return td::Unit{};
  }
};

int main(int argc, char **argv) {
  td::set_default_failure_signal_handler().ensure();
  std::string global, local, root;
  td::OptionParser parser;
  parser.add_option('C', "global-config", "test global configuration", [&](td::Slice s) { global = s.str(); });
  parser.add_option('c', "local-config", "test local configuration", [&](td::Slice s) { local = s.str(); });
  parser.add_option('D', "db", "test keys directory", [&](td::Slice s) { root = s.str(); });
  parser.add_option('v', "verbosity", "log level", [](td::Slice s) { SET_VERBOSITY_LEVEL(td::to_integer<int>(s)); });
  parser.run(argc, argv).ensure();
  td::actor::Scheduler scheduler({2});
  scheduler.run_in_context([&] { td::actor::create_actor<DhtFixture>("test-dht", global, local, root).release(); });
  scheduler.run();
}
