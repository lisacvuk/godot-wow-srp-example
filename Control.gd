extends Control

var realms = []

var socket: StreamPeerTCP

var username: String
var password: String

# Don't use this on actual servers
var server_address: String = "127.0.0.1"

enum AuthResult {
	WOW_SUCCESS = 0x00,
	WOW_FAIL_BANNED = 0x03,
	WOW_FAIL_UNKNOWN_ACCOUNT = 0x04,
	WOW_FAIL_INCORRECT_PASSWORD = 0x05,
	WOW_FAIL_ALREADY_ONLINE = 0x06
}

enum AuthCommand {
	AUTH_LOGON_CHALLENGE = 0x00,
	AUTH_LOGON_PROOF = 0x01,
	AUTH_RECONNECT_CHALLENGE = 0x02,
	AUTH_RECONNECT_PROOF = 0x03,
	REALM_LIST = 0x10
}

var sessionkey: PoolByteArray

func _ready():
	socket = StreamPeerTCP.new()

func _process(delta):
	if !socket.is_connected_to_host():
		return

	var available = socket.get_available_bytes()
	if available > 0:
		var cmd = socket.get_u8()
		match cmd:
			AuthCommand.AUTH_LOGON_CHALLENGE:
				process_challenge()
			AuthCommand.AUTH_LOGON_PROOF:
				process_proof_response()
			AuthCommand.REALM_LIST:
				process_realmlist_response()
			_:
				print("Unknown packet received!", str(cmd))

func error_reconnect():
	print("Something is wrong; attempting to reconnect...")
	attempt_reconnect()

func attempt_reconnect():
	socket.disconnect_from_host()
	socket.connect_to_host(server_address, 3724)
	# Hide the connect menu and display login status
	$Panel/CenterContainer/MenuConnect.hide()
	$Panel/CenterContainer/LoggingIn.show()
	# Start the authentification
	send_logon_chall()

func process_proof_response():
	var error = socket.get_u8()
	match error:
		AuthResult.WOW_SUCCESS:
			var m2 = socket.get_data(20)[1]
			var accountFlags = socket.get_u32()
			var surveyID = socket.get_u32()
			var loginFlags = socket.get_u16()
			if sessionkey == m2:
				request_realmlist()
			else:
				attempt_reconnect()
		AuthResult.WOW_FAIL_BANNED:
			print("Login failed: Account is banned.")
		AuthResult.WOW_FAIL_UNKNOWN_ACCOUNT:
			print("Login failed: Unknown account (this might also happen on wrong password).")
		AuthResult.WOW_FAIL_INCORRECT_PASSWORD:
			print("Login failed: Incorrect password.")
		AuthResult.WOW_FAIL_ALREADY_ONLINE:
			print("Login failed: Already online.")
		_:
			print("Login failed: Error code ", error)
	if socket.get_available_bytes() > 0:
		socket.get_data(socket.get_available_bytes())
		print("Error: Received spare bytes after packet data in process_proof_response")

func process_realmlist_response():
	var size = socket.get_u16()
	var wtf = socket.get_u32()
	var num_of_realms = socket.get_u16()
	for i in range(0, num_of_realms):
		var type = socket.get_u8()
		var status = socket.get_u8()
		var color = socket.get_u8()

		var realmname = ""
		var temp = socket.get_u8()
		while temp != 0x00:
			realmname += "%c" % temp
			temp = socket.get_u8()
		
		var serversocket = ""
		temp = socket.get_u8()
		while temp != 0x00:
			serversocket += "%c" % temp
			temp = socket.get_u8()
		
		serversocket = serversocket.split(":")
		
		var address = serversocket[0]
		var port = serversocket[1]
		
		var pop_level = socket.get_u32()
		var num_of_char = socket.get_u8()
		
		var timezone = socket.get_u8()
		
		var unk1 = socket.get_u16()
		var unk2 = socket.get_u8()
		
		realms.append({name = realmname, address = address, port = port})
		$Panel/CenterContainer/MenuRealm/Realms.add_item(realmname)
		
	if socket.get_available_bytes() > 0:
		socket.get_data(socket.get_available_bytes())
		print("Error: Received spare bytes after packet data in process_realmlist")

	$Panel/CenterContainer/MenuRealm.show()
	$Panel/CenterContainer/LoggingIn.hide()

func request_realmlist():
	status_update("Requesting realmlist...")
	var data = StreamPeerBuffer.new()
	data.put_u8(AuthCommand.REALM_LIST)
	data.put_u32(0)
	socket.put_data(data.get_data_array())

func process_challenge():
	status_update("Processing login challenge...")
	var error = socket.get_u8()
	var unk2 = socket.get_u8()
	var B = socket.get_data(32)[1]
	var g_len = socket.get_u8()
	var g = socket.get_u8()
	var n_len = socket.get_u8()
	var n = socket.get_data(32)[1]
	var s = socket.get_data(32)[1]
	var unk3 = socket.get_data(16)[1]
	var zero = socket.get_u8()

	if socket.get_available_bytes() > 0:
		socket.get_data(socket.get_available_bytes())
		print("Error: Received spare bytes after packet data in process_challenge")

	var WowSRP = Wow_SRP.new()
	var bootleg = PoolByteArray()
	bootleg.append(g)

	# Invert everything
	B.invert()
	s.invert()
	n.invert()

	WowSRP.step1(username, password, B.hex_encode(), bootleg.hex_encode(), n.hex_encode(), s.hex_encode())

	sessionkey = WowSRP.generateHashLogonProof()

	var S = WowSRP.get_S()
	var A = WowSRP.get_A()
	var M = WowSRP.get_M()
	var K = WowSRP.get_K()

	# Invert A
	A.invert()

	# Send the client proof
	var data = StreamPeerBuffer.new()
	data.put_u8(AuthCommand.AUTH_LOGON_PROOF)
	data.put_data(A)
	data.put_data(M)
	data.put_data(M)
	data.put_u8(0)
	data.put_u8(0)
	socket.put_data(data.get_data_array())

func send_logon_chall():
	status_update("Sending client info...")
	var data = StreamPeerBuffer.new()
	# Command
	data.put_u8(AuthCommand.AUTH_LOGON_CHALLENGE)
	# Error - didn't check why is this 0x03, but it works so whatever
	data.put_u8(0x03)
	# Size - TODO: This shouldn't be hardcoded
	data.put_u16(34)
	# Gamename
	data.put_data("WoW ".to_ascii())
	# Version
	data.put_u8(4)
	data.put_u8(3)
	data.put_u8(4)
	# Build
	data.put_u16(15595)
	# Platform
	data.put_data("68x ".to_ascii())
	# OS
	data.put_data("niW ".to_ascii())
	# Country
	data.put_data("SUne".to_ascii())
	# Timezone bias
	data.put_u8(60)
	data.put_u8(0)
	data.put_u8(0)
	data.put_u8(0)
	# IP
	data.put_u8(127)
	data.put_u8(0)
	data.put_u8(0)
	data.put_u8(1)
	# Username length
	data.put_u8(username.length())
	# Username
	data.put_data(username.to_ascii())
	var array = data.get_data_array()
	var size = array.size()
	socket.put_data(array)

func set_error(message: String):
	$Panel/CenterContainer/ErrorPopup.dialog_text = message
	$Panel/CenterContainer/ErrorPopup.popup_centered()

func status_update(message: String):
	$Panel/CenterContainer/LoggingIn/Status.text = message

func _on_Connect_pressed():
	username = $Panel/CenterContainer/MenuConnect/Username.text
	password = $Panel/CenterContainer/MenuConnect/Password.text
	
	if username.empty() or password.empty():
		set_error("Username and password cannot be empty.")
		return
	
	attempt_reconnect()

func _on_Cancel_pressed():
	socket.disconnect_from_host()
	$Panel/CenterContainer/LoggingIn.hide()
	$Panel/CenterContainer/MenuRealm.hide()
	$Panel/CenterContainer/MenuConnect.show()

func _on_Login_pressed():
	if $Panel/CenterContainer/MenuRealm/Realms.get_selected_items().empty():
		set_error("You must select a realm!")
		return
	var realm = realms[$Panel/CenterContainer/MenuRealm/Realms.get_selected_items()[0]]
	print("Connecting to ", realm.address, " port ", realm.port)
	pass
