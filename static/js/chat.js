/* 실시간 채팅 클라이언트.
 *
 * CSP가 script-src 'self'로 제한되어 인라인 <script>를 쓸 수 없으므로
 * 모든 로직을 이 외부 파일에 두고, 페이지별 값은 data-* 속성으로 받는다.
 */
(function () {
  "use strict";

  var root = document.getElementById("chat-root");
  if (!root) { return; }

  var myUserId  = root.getAttribute("data-user-id");
  var receiverId = root.getAttribute("data-receiver-id") || null;
  var scope = receiverId ? "dm" : "global";

  var socket   = io();
  var messages = document.getElementById("messages");
  var input    = document.getElementById("chat_input");
  var sendBtn  = document.getElementById("chat_send");

  function addMessage(username, text, isMine) {
    var li = document.createElement("li");
    if (isMine) { li.className = "mine"; }

    var who = document.createElement("span");
    who.className = "who";
    // [보안] textContent를 쓴다. innerHTML이었다면 사용자명이나 메시지에
    //        담긴 <script>가 그대로 실행되어 DOM 기반 XSS가 된다.
    who.textContent = username + ":";

    var body = document.createElement("span");
    body.textContent = text;

    li.appendChild(who);
    li.appendChild(body);
    messages.appendChild(li);
    messages.scrollTop = messages.scrollHeight;
  }

  socket.on("message", function (data) {
    if (!data || data.scope !== scope) { return; }
    if (scope === "dm" &&
        data.user_id !== myUserId && data.user_id !== receiverId) {
      return;
    }
    addMessage(data.username, data.message, data.user_id === myUserId);
  });

  socket.on("connect_error", function () {
    addMessage("시스템", "채팅 서버에 연결할 수 없습니다.", false);
  });

  function send() {
    var text = input.value.trim();
    if (!text) { return; }

    // ───────────────────────────────────────────────────────
    // [보안 수정 #6] username을 보내지 않는다.
    //
    // 베이스 코드는 이렇게 보냈다:
    //   socket.emit('send_message', { username: "{{ user.username }}", ... })
    // 신원을 클라이언트가 정하니 콘솔에서 'admin'으로 바꿔 보내면
    // 관리자 사칭이 됐다. 서버가 세션에서 신원을 판단하므로
    // 여기서는 메시지 본문(과 DM 대상)만 보낸다.
    // ───────────────────────────────────────────────────────
    var payload = { message: text };
    if (receiverId) { payload.receiver_id = receiverId; }

    socket.emit("send_message", payload);
    input.value = "";
    input.focus();
  }

  sendBtn.addEventListener("click", send);
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); send(); }
  });
})();
