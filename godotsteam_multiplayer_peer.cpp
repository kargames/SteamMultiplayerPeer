//===========================================================================//
// GodotSteam MultiplayerPeer - godotsteam_multiplayer_peer.cpp
//===========================================================================//
//
// Copyright (c) 2017-Current | Chris Ridenour, Ryan Leverenz and Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//===========================================================================//

#include "godotsteam_multiplayer_peer.h"

#define MAX_MESSAGE_COUNT 255

SteamMultiplayerPeer::SteamMultiplayerPeer()
    : callback_network_connection_status_changed(
          this, &SteamMultiplayerPeer::network_connection_status_changed),
      callback_lobby_chat_update(this,
                                 &SteamMultiplayerPeer::lobby_chat_update) {}

SteamMultiplayerPeer::~SteamMultiplayerPeer() { close(); }

void SteamMultiplayerPeer::set_target_peer(int p_peer_id) {
  target_peer = p_peer_id;
}

int SteamMultiplayerPeer::get_packet_peer() const {
  ERR_FAIL_COND_V(incoming_packets.is_empty(), 1);

  return SteamNetworkingSockets()->GetConnectionUserData(
      incoming_packets.front()->get()->m_conn);
}

MultiplayerPeer::TransferMode SteamMultiplayerPeer::get_packet_mode() const {
  ERR_FAIL_COND_V(incoming_packets.is_empty(), TRANSFER_MODE_RELIABLE);
  if (incoming_packets.front()->get()->m_nFlags &
      k_nSteamNetworkingSend_Reliable) {
    return TRANSFER_MODE_RELIABLE;
  } else {
    return TRANSFER_MODE_UNRELIABLE;
  }
}

int SteamMultiplayerPeer::get_packet_channel() const {
  ERR_FAIL_COND_V(incoming_packets.is_empty(), 1);
  return incoming_packets.front()->get()->m_idxLane;
}

void SteamMultiplayerPeer::disconnect_peer(int p_peer_id, bool p_force) {
  // Let godot know our peer disconnected and erase from our maps
  if (peers.has(p_peer_id)) {
    peers[p_peer_id]->disconnect_peer(p_force);
    emit_signal(SNAME("peer_disconnected"), p_peer_id);
    steam_connections.erase(peers[p_peer_id]->get_connection_handle());
  }

  // Clean up our local state
  peers.erase(p_peer_id);

  // Close if this was the host we lost
  if (p_peer_id == 1 && connection_status != CONNECTION_DISCONNECTED) {
    close();
  }
}

bool SteamMultiplayerPeer::is_server() const { return server; }

void SteamMultiplayerPeer::poll() {
  SteamNetworkingMessage_t *messages[MAX_MESSAGE_COUNT];
  int number_messages = SteamNetworkingSockets()->ReceiveMessagesOnPollGroup(
      poll_group, messages, MAX_MESSAGE_COUNT);
  if (number_messages == 0) {
    return;
  }

  for (int i = 0; i < number_messages; i++) {
    SteamNetworkingMessage_t *message = messages[i];

    if (SteamNetworkingSockets()->GetConnectionUserData(message->m_conn) <= 0) {
      // Do we have any pending peers waiting for a peer_id
      if (steam_connections.has(message->m_conn)) {
        if (steam_connections[message->m_conn]->process_ping(message) == OK) {
          if (steam_connections[message->m_conn]->get_state() ==
              SteamPacketPeer::STATE_CONNECTED) {
            upgrade_peer(message->m_conn);
          }
        }
      } else {
        if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
          WARN_PRINT("Packet received with no associated peer.");
        }
      }

      message->Release();
    } else {
      incoming_packets.push_back(message);
    }
  }
}

void SteamMultiplayerPeer::network_connection_status_changed(
    SteamNetConnectionStatusChangedCallback_t *p_status_change) {
  if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
    WARN_PRINT(vformat(
        "Connection from %ud changed from %ud to %ud",

        (uint64_t)p_status_change->m_info.m_identityRemote.GetSteamID64(),
        p_status_change->m_eOldState, p_status_change->m_info.m_eState));
  }

  // Check the state of the connection
  switch (p_status_change->m_info.m_eState) {
    // Do nothing
  case k_ESteamNetworkingConnectionState_None:
  case k_ESteamNetworkingConnectionState_ClosedByPeer:
  case k_ESteamNetworkingConnectionState_ProblemDetectedLocally: {
    if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
      WARN_PRINT(vformat("Connection closed with reason %ud: %s",
                         p_status_change->m_info.m_eEndReason,
                         p_status_change->m_info.m_szEndDebug));
    }
    // Determine if we were previously connected
    if (p_status_change->m_eOldState ==
        k_ESteamNetworkingConnectionState_Connected) {
      uint32_t connection_peer_id = p_status_change->m_info.m_nUserData;
      disconnect_peer(connection_peer_id, true);
      // Erase directly from the status_change in case it was a lingering connection.
      steam_connections.erase(p_status_change->m_hConn);
    }

    // Clean up the connection, but the reason does not matter since it was
    // closed on the other end
    SteamNetworkingSockets()->CloseConnection(p_status_change->m_hConn, 0,
                                              nullptr, false);

    // If we were the client, attempt to reconnect
    if (p_status_change->m_eOldState == k_ESteamNetworkingConnectionState_Connecting 
      && p_status_change->m_info.m_eEndReason == k_ESteamNetConnectionEnd_Remote_BadCert 
      && connection_retries < 5) {
        if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
          WARN_PRINT("Attempting to reconnect after bad cert.");
        }
      add_peer(p_status_change->m_info.m_identityRemote.GetSteamID64());
      connection_retries++;
    }
    break;
  }
  // A new incoming connection we should handle
  case k_ESteamNetworkingConnectionState_Connecting: {
    if (listen_socket != k_HSteamListenSocket_Invalid &&
        p_status_change->m_info.m_hListenSocket == listen_socket) {
      if (is_refusing_new_connections()) {
        if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
          WARN_PRINT("Connection refused because Godot peer is refusing "
                     "connections.");
        }
        return;
      }

      if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
        WARN_PRINT(vformat(
            "Connection attempt from %ud.",
            (uint64_t)p_status_change->m_info.m_identityRemote.GetSteamID64()));
      }

      uint32_t connection_peer_id = p_status_change->m_info.m_nUserData;
      ERR_FAIL_COND_MSG(
          peers.has(connection_peer_id),
          vformat("Attempting to connect peer %d but it already exists.",
                  connection_peer_id));

      if (SteamNetworkingSockets()->AcceptConnection(
              p_status_change->m_hConn) != k_EResultOK) {
        SteamNetworkingSockets()->CloseConnection(p_status_change->m_hConn, 0,
                                                  nullptr, false);
        WARN_PRINT("A connection was started but couldn't be accepted.");
        return;
      } else {
        if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
          WARN_PRINT("Connection accepted.");
        }
      }
    }

    // Regardless of who created the connection, since we're symmetrical we
    // want to keep track of everything Add it to our poll group
    if (!SteamNetworkingSockets()->SetConnectionPollGroup(
            p_status_change->m_hConn, poll_group)) {
      SteamNetworkingSockets()->CloseConnection(p_status_change->m_hConn, 0,
                                                nullptr, false);
      WARN_PRINT("A connection was abandoned because it could not be added to "
                 "a poll group.");
      return;
    }

    // Create our packet peer
    _add_pending_peer(p_status_change->m_info.m_identityRemote.GetSteamID64(),
                      p_status_change->m_hConn,
                      SteamPacketPeer::PeerState::STATE_CONNECTING);
    break;
  }
  case k_ESteamNetworkingConnectionState_Connected: {
    // Someone has finished connecting to us
    connection_retries = 0;
    if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
      WARN_PRINT(vformat(
          "Attempting to send peer ID to %ud",
          (uint64_t)p_status_change->m_info.m_identityRemote.GetSteamID64()));
    }
    if (steam_connections.has(p_status_change->m_hConn)) {

      steam_connections[p_status_change->m_hConn]->set_state(
          (SteamPacketPeer::PeerState)p_status_change->m_info.m_eState);
      // Then send our Peer ID
      Error ping_result =
          steam_connections[p_status_change->m_hConn]->ping(get_unique_id());
      if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
        WARN_PRINT(vformat(
            "Ping sent to %ud: %d",
            (uint64_t)p_status_change->m_info.m_identityRemote.GetSteamID64(),
            ping_result));
      }

      // If we already have their peer ID, upgrade it
      if (steam_connections[p_status_change->m_hConn]->get_peer_id() > 0) {
        upgrade_peer(p_status_change->m_hConn);
      }
    } else {
      ERR_PRINT("A connection was established without a peer being created.");
    }

    break;
  }
  // Pass this off to the peer, and update its state
  // If it doesn't exist, do nothing
  default: {
    if (steam_connections.has(p_status_change->m_hConn)) {
      steam_connections[p_status_change->m_hConn]->set_state(
          (SteamPacketPeer::PeerState)p_status_change->m_info.m_eState);
    }
    break;
  }
  }
}

void SteamMultiplayerPeer::lobby_chat_update(LobbyChatUpdate_t *p_chat_update) {
  if (p_chat_update->m_ulSteamIDLobby != tracked_lobby.ConvertToUint64()) {
    if (unlikely(debug_level > DEBUG_LEVEL_NONE)) {
      WARN_PRINT(vformat("LobbyChatUpdate ignored due to lobby ID mismatch: "
                         "Expecting: %ud, Received: %d",
                         (uint64_t)tracked_lobby.ConvertToUint64(),
                         (uint64_t)p_chat_update->m_ulSteamIDLobby));
    }
    return;
  }

  if (p_chat_update->m_ulSteamIDUserChanged ==
      SteamUser()->GetSteamID().ConvertToUint64()) {
    // Ignore updates about ourselves
    return;
  }

  if (p_chat_update->m_rgfChatMemberStateChange &
      k_EChatMemberStateChangeEntered) {
    add_peer(p_chat_update->m_ulSteamIDUserChanged);
  } else {
    // If they didn't enter, it doesn't matter why, they are leaving
    for (KeyValue<HSteamNetConnection, Ref<SteamPacketPeer>> &E :
         steam_connections) {
      if (E.value->get_steam_id() == p_chat_update->m_ulSteamIDUserChanged) {
        if (E.value->get_peer_id() > 0) {
          disconnect_peer(E.value->get_peer_id());
        } else {
          // We have an open connection but no peer
          E.value->disconnect_peer(true);
          steam_connections.erase(E.value->get_connection_handle());
        }
      }
    }
  }
}

void SteamMultiplayerPeer::close() {
  connection_status = CONNECTION_DISCONNECTED;
  server = false;

  for (KeyValue<HSteamNetConnection, Ref<SteamPacketPeer>> &E :
       steam_connections) {
    E.value->disconnect_peer(true);
  }
  steam_connections.clear();
  peers.clear();

  // Clear any remaining packets
  if (current_packet != nullptr) {
    current_packet->Release();
    current_packet = nullptr;
  }

  while (!incoming_packets.is_empty()) {
    SteamNetworkingMessage_t *packet = incoming_packets.front()->get();
    incoming_packets.pop_front();
    packet->Release();
  }

  incoming_packets.clear();

  // Close any open sockets
  if (listen_socket != k_HSteamListenSocket_Invalid) {
    SteamNetworkingSockets()->CloseListenSocket(listen_socket);
    listen_socket = k_HSteamListenSocket_Invalid;
  }

  if (poll_group != k_HSteamNetPollGroup_Invalid) {
    SteamNetworkingSockets()->DestroyPollGroup(poll_group);
    poll_group = k_HSteamNetPollGroup_Invalid;
  }
}

int SteamMultiplayerPeer::get_unique_id() const { return unique_id; }

MultiplayerPeer::ConnectionStatus
SteamMultiplayerPeer::get_connection_status() const {
  return connection_status;
}

int SteamMultiplayerPeer::get_available_packet_count() const {
  return incoming_packets.size();
}

Error SteamMultiplayerPeer::get_packet(const uint8_t **r_buffer,
                                       int &r_buffer_size) {
  ERR_FAIL_COND_V_MSG(incoming_packets.is_empty(), ERR_UNAVAILABLE,
                      "No incoming packets available.");

  if (current_packet != nullptr) {
    current_packet->Release();
    current_packet = nullptr;
  }

  current_packet = incoming_packets.front()->get();
  incoming_packets.pop_front();

  *r_buffer = (uint8_t *)current_packet->GetData();
  r_buffer_size = current_packet->GetSize();

  return OK;
}

Error SteamMultiplayerPeer::put_packet(const uint8_t *p_buffer,
                                       int p_buffer_size) {
  ERR_FAIL_COND_V_MSG(connection_status != CONNECTION_CONNECTED,
                      ERR_UNCONFIGURED,
                      "The multiplayer instance isn't currently connected to "
                      "any server or client.");
  ERR_FAIL_COND_V_MSG(target_peer != 0 && !peers.has(ABS(target_peer)),
                      ERR_INVALID_PARAMETER,
                      vformat("Invalid target peer: %d", target_peer));

  if (target_peer == 0) {
    // Send to all peers
    for (KeyValue<uint32_t, Ref<SteamPacketPeer>> &E : peers) {
      E.value->send(get_transfer_channel(), p_buffer, p_buffer_size,
                    _get_steam_packet_flags());
    }
  } else if (peers.has(target_peer)) {
    // Send to specific peer
    Ref<SteamPacketPeer> peer = peers[target_peer];
    return peer->send(get_transfer_channel(), p_buffer, p_buffer_size,
                      _get_steam_packet_flags());
  } else if (target_peer < 0) {
    // We're in weird exclusion territory
    int exclude = ABS(target_peer);
    for (KeyValue<uint32_t, Ref<SteamPacketPeer>> &E : peers) {
      if (E.key == exclude) {
        continue;
      }
      E.value->send(get_transfer_channel(), p_buffer, p_buffer_size,
                    _get_steam_packet_flags());
    }
  }

  return OK;
}

int SteamMultiplayerPeer::get_max_packet_size() const {
  // Steam networking sockets max message size
  return k_cbMaxSteamNetworkingSocketsMessageSizeSend; // 512 KB
}

Error SteamMultiplayerPeer::_create_listen_socket(int p_virtual_port) {
  SteamNetworkingConfigValue_t opt[2];
  opt[0].SetInt32(k_ESteamNetworkingConfig_SymmetricConnect, 1);
  listen_socket =
      SteamNetworkingSockets()->CreateListenSocketP2P(p_virtual_port, 1, opt);

  ERR_FAIL_COND_V(listen_socket == k_HSteamListenSocket_Invalid,
                  ERR_CANT_CREATE);

  return OK;
}

Error SteamMultiplayerPeer::_create_poll_group() {
  poll_group = SteamNetworkingSockets()->CreatePollGroup();
  ERR_FAIL_COND_V(poll_group == k_HSteamNetPollGroup_Invalid, ERR_CANT_CREATE);

  return OK;
}

Error SteamMultiplayerPeer::create_host(int p_virtual_port) {
  ERR_FAIL_COND_V(connection_status != CONNECTION_DISCONNECTED,
                  ERR_ALREADY_IN_USE);

  server = true;
  unique_id = 1; // Server is always peer ID 1

  Error socket_created = _create_listen_socket(p_virtual_port);
  ERR_FAIL_COND_V(socket_created != OK, socket_created);

  Error poll_group_created = _create_poll_group();
  ERR_FAIL_COND_V(poll_group_created != OK, poll_group_created);

  set_refuse_new_connections(false);
  connection_status = CONNECTION_CONNECTED;
  return OK;
}

Error SteamMultiplayerPeer::create_client(uint64_t p_host_steam_id,
                                          int p_virtual_port) {
  ERR_FAIL_COND_V(connection_status != CONNECTION_DISCONNECTED,
                  ERR_ALREADY_IN_USE);

  server = false;
  connection_retries = 0;
  unique_id = generate_unique_id();

  // We create a listen socket in all cases as we need to handle true P2P
  Error socket_created = _create_listen_socket(p_virtual_port);
  ERR_FAIL_COND_V(socket_created != OK, socket_created);

  Error poll_group_created = _create_poll_group();
  ERR_FAIL_COND_V(poll_group_created != OK, poll_group_created);

  Error peer_created = add_peer(p_host_steam_id, p_virtual_port);
  ERR_FAIL_COND_V(peer_created != OK, peer_created);

  set_refuse_new_connections(false);
  connection_status = CONNECTION_CONNECTING;

  return OK;
}

Error SteamMultiplayerPeer::add_peer(uint64_t p_steam_id, int p_virtual_port) {
  SteamNetworkingIdentity remote_identity;
  remote_identity.SetSteamID64(p_steam_id);

  SteamNetworkingConfigValue_t opt[2];
  opt[0].SetInt32(k_ESteamNetworkingConfig_SymmetricConnect, 1);

  HSteamNetConnection connection = SteamNetworkingSockets()->ConnectP2P(
      remote_identity, p_virtual_port, 1, opt);

  ERR_FAIL_COND_V(connection == k_HSteamNetConnection_Invalid, ERR_CANT_CREATE);

  return OK;
}

void SteamMultiplayerPeer::_add_pending_peer(
    uint64_t p_steam_id, HSteamNetConnection p_connection_handle,
    SteamPacketPeer::PeerState p_peer_state) {
  Ref<SteamPacketPeer> peer = memnew(SteamPacketPeer);
  peer->set_steam_id(p_steam_id);
  peer->set_connection_handle(p_connection_handle);
  peer->set_state(p_peer_state);

  steam_connections[p_connection_handle] = peer;
}

void SteamMultiplayerPeer::upgrade_peer(
    HSteamNetConnection p_connection_handle) {
  if (steam_connections.has(p_connection_handle)) {
    peers[steam_connections[p_connection_handle]->get_peer_id()] =
        steam_connections[p_connection_handle];
    // Since we have at least one peer connected, let's upgrade our connection
    // status
    if (connection_status == CONNECTION_CONNECTING) {
      connection_status = CONNECTION_CONNECTED;
    }
    emit_signal(SNAME("peer_connected"),
                steam_connections[p_connection_handle]->get_peer_id());
  }
}

Ref<SteamPacketPeer> SteamMultiplayerPeer::get_peer(int p_peer_id) {
  if (peers.has(p_peer_id)) {
    return peers[p_peer_id];
  }
  return nullptr;
}

Error SteamMultiplayerPeer::host_with_lobby(uint64_t p_lobby_id) {
  ERR_FAIL_COND_V(connection_status != CONNECTION_DISCONNECTED,
                  ERR_ALREADY_IN_USE);
  CSteamID lobby;
  lobby.SetFromUint64(p_lobby_id);
  ERR_FAIL_COND_V_MSG(SteamMatchmaking()->GetLobbyOwner(lobby) == k_steamIDNil,
                      ERR_CANT_CREATE,
                      "You must be a member of the lobby you are trying to "
                      "connect with the SteamMultiplayerPeer.");
  ERR_FAIL_COND_V_MSG(
      SteamMatchmaking()->GetLobbyOwner(lobby) != SteamUser()->GetSteamID(),
      ERR_CANT_CREATE,
      vformat("You must be the owner of the lobby you are trying to "
              "host with SteamMultiplayerPeer."));

  tracked_lobby = lobby;

  Error host_created = create_host();
  ERR_FAIL_COND_V(host_created != OK, host_created);

  // In case the lobby already has members, let's connect to them
  int count = SteamMatchmaking()->GetNumLobbyMembers(lobby);
  for (int i = 0; i < count; i++) {
    CSteamID member = SteamMatchmaking()->GetLobbyMemberByIndex(lobby, i);
    if (member != SteamUser()->GetSteamID()) {
      add_peer(member.ConvertToUint64());
    }
  }

  return OK;
}

Error SteamMultiplayerPeer::connect_to_lobby(uint64_t p_lobby_id) {
  ERR_FAIL_COND_V(connection_status != CONNECTION_DISCONNECTED,
                  ERR_ALREADY_IN_USE);
  CSteamID lobby;
  lobby.SetFromUint64(p_lobby_id);
  ERR_FAIL_COND_V_MSG(SteamMatchmaking()->GetLobbyOwner(lobby) == k_steamIDNil,
                      ERR_CANT_CREATE,
                      "You must be a member of the lobby you are trying to "
                      "connect with the SteamMultiplayerPeer.");

  tracked_lobby = lobby;

  Error client_created =
      create_client(SteamMatchmaking()->GetLobbyOwner(lobby).ConvertToUint64());
  ERR_FAIL_COND_V(client_created != OK, client_created);

  // Connect to the rest of the members
  int count = SteamMatchmaking()->GetNumLobbyMembers(lobby);
  for (int i = 0; i < count; i++) {
    CSteamID member = SteamMatchmaking()->GetLobbyMemberByIndex(lobby, i);
    if (member != SteamUser()->GetSteamID() &&
        member != SteamMatchmaking()->GetLobbyOwner(lobby)) {
      add_peer(member.ConvertToUint64());
    }
  }

  return OK;
}

void SteamMultiplayerPeer::set_no_nagle(const bool p_no_nagle) {
  no_nagle = p_no_nagle;
}

bool SteamMultiplayerPeer::get_no_nagle() const { return no_nagle; }

void SteamMultiplayerPeer::set_no_delay(const bool p_no_delay) {
  no_delay = p_no_delay;
}

bool SteamMultiplayerPeer::get_no_delay() const { return no_delay; }

extern "C" void __cdecl SteamAPIDebugTextHook(int nSeverity,
                                              const char *pchDebugText) {
  WARN_PRINT(pchDebugText);
}

void SteamMultiplayerPeer::set_debug_level(DebugLevel p_debug_level) {
  debug_level = p_debug_level;
  if (debug_level >= DEBUG_LEVEL_STEAM) {
    SteamUtils()->SetWarningMessageHook(&SteamAPIDebugTextHook);
  } else {
    SteamUtils()->SetWarningMessageHook(nullptr);
  }
}
SteamMultiplayerPeer::DebugLevel SteamMultiplayerPeer::get_debug_level() const {
  return debug_level;
}

const int SteamMultiplayerPeer::_get_steam_packet_flags() {

  int32_t flags = (k_nSteamNetworkingSend_NoNagle * no_nagle) |
                  (k_nSteamNetworkingSend_NoDelay * no_delay);

  switch (get_transfer_mode()) {
  case TransferMode::TRANSFER_MODE_RELIABLE:
    return k_nSteamNetworkingSend_Reliable | flags;
    break;
  case TransferMode::TRANSFER_MODE_UNRELIABLE:
    return k_nSteamNetworkingSend_Unreliable | flags;
    break;
  case TransferMode::TRANSFER_MODE_UNRELIABLE_ORDERED:
    // No equivalent
    return k_nSteamNetworkingSend_Reliable | flags;
    break;
  }

  ERR_FAIL_V_MSG(-1, "Error determining SteamNetworkingSend flags.");
}

uint64_t SteamMultiplayerPeer::get_steam_id_for_peer_id(int p_peer_id) {
  if (p_peer_id == unique_id) {
    return SteamUser()->GetSteamID().ConvertToUint64();
  }

  if (peers.has(p_peer_id)) {
    return peers[p_peer_id]->get_steam_id();
  }

  return 0;
}

int SteamMultiplayerPeer::get_peer_id_for_steam_id(uint64_t p_steam_id) {
  if (p_steam_id == SteamUser()->GetSteamID().ConvertToUint64()) {
    return unique_id;
  }

  for (KeyValue<uint32_t, Ref<SteamPacketPeer>> &E : peers) {
    if (E.value->get_steam_id() == p_steam_id) {
      return E.key;
    }
  }

  return 0;
}

void SteamMultiplayerPeer::_bind_methods() {
  ClassDB::bind_method(D_METHOD("create_host", "virtual_port"),
                       &SteamMultiplayerPeer::create_host, DEFVAL(0));
  ClassDB::bind_method(D_METHOD("create_client", "steam_id", "virtual_port"),
                       &SteamMultiplayerPeer::create_client, DEFVAL(0));
  ClassDB::bind_method(D_METHOD("add_peer", "steam_id", "virtual_port"),
                       &SteamMultiplayerPeer::add_peer, DEFVAL(0));
  ClassDB::bind_method(D_METHOD("get_peer", "peer_id"),
                       &SteamMultiplayerPeer::get_peer);

  ClassDB::bind_method(D_METHOD("host_with_lobby", "lobby_id"),
                       &SteamMultiplayerPeer::host_with_lobby);
  ClassDB::bind_method(D_METHOD("connect_to_lobby", "lobby_id"),
                       &SteamMultiplayerPeer::connect_to_lobby);

  ClassDB::bind_method(D_METHOD("get_steam_id_for_peer_id", "peer_id"),
                       &SteamMultiplayerPeer::get_steam_id_for_peer_id);
  ClassDB::bind_method(D_METHOD("get_peer_id_for_steam_id", "steam_id"),
                       &SteamMultiplayerPeer::get_peer_id_for_steam_id);

  ClassDB::bind_method(D_METHOD("get_no_delay"),
                       &SteamMultiplayerPeer::get_no_delay);
  ClassDB::bind_method(D_METHOD("set_no_delay"),
                       &SteamMultiplayerPeer::set_no_delay);
  ClassDB::bind_method(D_METHOD("get_no_nagle"),
                       &SteamMultiplayerPeer::get_no_nagle);
  ClassDB::bind_method(D_METHOD("set_no_nagle"),
                       &SteamMultiplayerPeer::set_no_nagle);
  ClassDB::bind_method(D_METHOD("get_debug_level"),
                       &SteamMultiplayerPeer::get_debug_level);
  ClassDB::bind_method(D_METHOD("set_debug_level"),
                       &SteamMultiplayerPeer::set_debug_level);

  ADD_PROPERTY(PropertyInfo(Variant::BOOL, "no_delay"), "set_no_delay",
               "get_no_delay");
  ADD_PROPERTY(PropertyInfo(Variant::BOOL, "no_nagle"), "set_no_nagle",
               "get_no_nagle");
  ADD_PROPERTY(PropertyInfo(Variant::INT, "debug_level", PROPERTY_HINT_ENUM,
                            "None,Peer,Steam"),
               "set_debug_level", "get_debug_level");

  BIND_ENUM_CONSTANT(DEBUG_LEVEL_NONE);
  BIND_ENUM_CONSTANT(DEBUG_LEVEL_PEER);
  BIND_ENUM_CONSTANT(DEBUG_LEVEL_STEAM);
}
