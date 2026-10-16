/*
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "http/http.h"
#include "td/utils/tests.h"

TEST(ProxyHttp, CompletedBodyFitsFinalPart) {
  std::string body(835643, 'x');
  td::ChainBufferWriter writer;
  writer.append(td::Slice(body));
  auto input = writer.extract_reader();
  ton::http::HttpPayload payload(ton::http::HttpPayload::PayloadType::pt_content_length,
      ton::http::HttpResponse::low_watermark(), 1 << 20, body.size());
  payload.parse(input).ensure();
  ASSERT_TRUE(payload.parse_completed());
  auto part = payload.store_tl(2 << 20);
  ASSERT_EQ(part->data_.as_slice(), td::Slice(body));
  ASSERT_TRUE(part->last_);
  ASSERT_TRUE(payload.written());
}

TEST(ProxyHttp, CompletedContentLengthAboveHighWatermark) {
  const size_t high = 1 << 20;
  std::string body(high + 14 * 1024, 'x');
  td::ChainBufferWriter writer;
  writer.append(td::Slice(body));
  auto input = writer.extract_reader();
  ton::http::HttpPayload payload(ton::http::HttpPayload::PayloadType::pt_content_length,
      ton::http::HttpResponse::low_watermark(), high, body.size());
  payload.parse(input).ensure();
  ASSERT_EQ(input.size(), 0u);
  ASSERT_TRUE(payload.parse_completed());
  auto part = payload.store_tl(2 << 20);
  ASSERT_EQ(part->data_.as_slice(), td::Slice(body));
  ASSERT_TRUE(part->last_);
  ASSERT_TRUE(payload.written());
}

TEST(ProxyHttp, IncompleteContentLengthAboveHighWatermark) {
  const size_t high = 1 << 20;
  std::string body(high + 14 * 1024, 'x');
  td::ChainBufferWriter writer;
  writer.append(td::Slice(body));
  auto input = writer.extract_reader();
  ton::http::HttpPayload payload(ton::http::HttpPayload::PayloadType::pt_content_length,
      ton::http::HttpResponse::low_watermark(), high, body.size() + 16384);
  payload.parse(input).ensure();
  ASSERT_EQ(input.size(), 0u);
  ASSERT_TRUE(payload.high_watermark_reached());
  ASSERT_TRUE(!payload.parse_completed());
  auto part = payload.store_tl(2 << 20);
  ASSERT_EQ(part->data_.as_slice(), td::Slice(body));
  ASSERT_TRUE(!part->last_);
}

TEST(ProxyHttp, BodyFailureWakesBothActors) {
  struct Callback : ton::http::HttpPayload::Callback {
    explicit Callback(int &calls) : calls(calls) {}
    void run(size_t) override {}
    void completed() override { calls++; }
    int &calls;
  };
  ton::http::HttpPayload payload(ton::http::HttpPayload::PayloadType::pt_eof, 16384, 1048576);
  int producer = 0, consumer = 0, late = 0;
  payload.add_callback(std::make_unique<Callback>(producer));
  payload.add_callback(std::make_unique<Callback>(consumer));
  payload.set_error();
  payload.set_error();
  payload.add_callback(std::make_unique<Callback>(late));
  ASSERT_TRUE(payload.is_error());
  ASSERT_EQ(producer, 1);
  ASSERT_EQ(consumer, 1);
  ASSERT_EQ(late, 1);
}

TEST(ProxyHttp, PayloadBuffersArePerInstance) {
  const std::string body(256 * 1024, 'b');
  auto request = ton::http::HttpRequest::create("POST", "/", "HTTP/1.1").move_as_ok();
  auto response = ton::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  auto verify = [&](auto &message) {
    message->add_header({"Content-Length", std::to_string(body.size())}).ensure();
    message->complete_parse_header().ensure();
    auto original = message->create_empty_payload().move_as_ok();
    auto optimized = message->create_empty_payload(1 << 20).move_as_ok();
    auto original_again = message->create_empty_payload().move_as_ok();
    for (auto payload : {original, optimized, original_again}) {
      td::ChainBufferWriter writer;
      writer.append(td::Slice(body));
      auto input = writer.extract_reader();
      payload->parse(input).ensure();
      if (payload == optimized) {
        ASSERT_EQ(input.size(), 0u);
        ASSERT_TRUE(payload->parse_completed());
        ASSERT_EQ(payload->store_tl(body.size())->data_.as_slice(), td::Slice(body));
      } else {
        ASSERT_TRUE(payload->ready_bytes() > 128 * 1024u);
        ASSERT_TRUE(payload->ready_bytes() <= 128 * 1024u + 16384u);
        ASSERT_TRUE(input.size() > 0);
        ASSERT_TRUE(!payload->parse_completed());
      }
    }
  };
  verify(request);
  verify(response);
}

TEST(ProxyHttp, NoBodyResponseSurvivesTlSerialization) {
  for (auto code : {200u, 204u, 304u}) {
    auto response = ton::http::HttpResponse::create("HTTP/1.1", code, "Test", code == 200, true).move_as_ok();
    response->add_header({"Content-Length", "12345"}).ensure();
    response->complete_parse_header().ensure();
    auto wire = response->store_tl();
    ASSERT_TRUE(wire->no_payload_);
    auto decoded = ton::http::HttpResponse::create(wire->http_version_, wire->status_code_, wire->reason_,
                                                 wire->no_payload_, true).move_as_ok();
    for (auto &header : wire->headers_) {
      decoded->add_header({header->name_, header->value_}).ensure();
    }
    decoded->complete_parse_header().ensure();
    ASSERT_TRUE(decoded->create_empty_payload().move_as_ok()->parse_completed());
  }
  auto response = ton::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, true).move_as_ok();
  ASSERT_TRUE(!response->store_tl()->no_payload_);
}
