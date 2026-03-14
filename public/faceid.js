// faceid.js

const API_URL = window.location.origin;

const guideEl = document.getElementById("guide-text");
const canvas = document.getElementById("matrix-bg");
const ctx = canvas.getContext("2d");
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
const katakana = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
const alphabet = katakana.split("");
const fontSize = 16;
const columns = canvas.width / fontSize;
const drops = [];
for (let x = 0; x < columns; x++) drops[x] = 1;

function drawMatrix() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#0F0";
  ctx.font = fontSize + "px monospace";
  for (let i = 0; i < drops.length; i++) {
    const text = alphabet[Math.floor(Math.random() * alphabet.length)];
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975)
      drops[i] = 0;
    drops[i]++;
  }
}
setInterval(drawMatrix, 30);

const THEME_COLOR = "#00f3ff";
const ALERT_COLOR = "rgba(255, 0, 60, 1)";
const SUCCESS_COLOR = "#00ff00";
const LINE_WIDTH = 3;
const GLOW_AMOUNT = 15;

const FACE_MODEL_URL = "https://justadudewhohacks.github.io/face-api.js/models";

const UNLOCK_THRESHOLD = 0.44;
const TARGET_SAMPLES = 40;
const REQUIRED_MATCHES = 25;

const videoElement = document.getElementById("video");
const canvasOverlay = document.getElementById("overlay");
const ctxOverlay = canvasOverlay.getContext("2d");
const statusText = document.getElementById("status-text");
const messageEl = document.getElementById("message");
const lockIcon = document.getElementById("lock-icon");
const progressBar = document.getElementById("progress-fill");
const laser = document.querySelector(".laser-scan");
const clock = document.getElementById("clock");
const scanStatusOverlay = document.getElementById("scan-status-overlay");
const terminalContainer = document.getElementById("main-terminal");
const videoMask = document.querySelector(".video-mask");

const btnEnroll = document.getElementById("btn-enroll");
const btnDelete = document.getElementById("btn-delete");

let faceMatcher = null;
let currentMode = "INIT";
let enrollDescriptors = [];
let lastFaceCheckTime = 0;
let isSystemReady = false;
let isProcessingFace = false;
let isSaving = false;
let isSuccessLocked = false;

let matchCounter = 0;

function hackerTextEffect(element, finalText) {
  let iterations = 0;
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const interval = setInterval(() => {
    element.innerText = finalText
      .split("")
      .map((letter, index) => {
        if (index < iterations) return finalText[index];
        return letters[Math.floor(Math.random() * letters.length)];
      })
      .join("");
    if (iterations >= finalText.length) clearInterval(interval);
    iterations += 1 / 3;
  }, 30);
}

setInterval(() => {
  const now = new Date();
  if (clock) clock.innerText = now.toLocaleTimeString();
  const cpu = document.getElementById("cpu-stat");
  if (cpu) cpu.innerText = Math.floor(Math.random() * 100) + "%";
}, 1000);

async function initSystem() {
  hackerTextEffect(messageEl, "> INITIALIZING CORE...");
  try {
    await Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri(FACE_MODEL_URL),
      faceapi.nets.faceLandmark68Net.loadFromUri(FACE_MODEL_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(FACE_MODEL_URL),
    ]);

    await checkServerData();

    startCameraPipeline();
    isSystemReady = true;
  } catch (err) {
    console.error(err);
    messageEl.innerText = "> ERROR: MODEL LOAD FAILED";
  }
}

async function checkServerData() {
  hackerTextEffect(messageEl, "> SYNCING WITH SERVER DB...");
  try {
    const res = await fetch(`${API_URL}/face-id/load`);
    const json = await res.json();

    if (json.success && json.data && json.data.length > 0) {
      loadMatcher(json.data);
      setMode("CHECK");
      hackerTextEffect(messageEl, "> DATA SYNCED. SYSTEM ARMED.");
    } else {
      setMode("IDLE");
    }
  } catch (e) {
    console.error("Lỗi tải Face ID:", e);
    hackerTextEffect(messageEl, "> SERVER ERROR. OFFLINE MODE.");
    setMode("IDLE");
  }
}

function setMode(mode) {
  currentMode = mode;
  progressBar.style.width = "0%";
  laser.style.display = "none";
  isSaving = false;
  matchCounter = 0;

  if (mode === "IDLE") {
    hackerTextEffect(statusText, "SYSTEM IDLE");
    hackerTextEffect(messageEl, "> NO DATA. REGISTER NEW ADMIN.");
    lockIcon.className = "fa-solid fa-lock";
    lockIcon.style.color = "var(--neon-green)";

    btnEnroll.style.display = "block";
    btnEnroll.innerHTML = '<span class="btn-content">THIẾT LẬP FACE ID</span>';

    btnDelete.style.display = "none";
  } else if (mode === "ENROLL") {
    hackerTextEffect(statusText, "RECORDING...");
    hackerTextEffect(messageEl, "> ROTATE HEAD SLIGHTLY...");
    enrollDescriptors = [];
    laser.style.display = "block";

    btnEnroll.style.display = "block";
    btnEnroll.innerHTML = '<span class="btn-content">HỦY BỎ</span>';

    btnDelete.style.display = "none";
  } else if (mode === "CHECK") {
    hackerTextEffect(statusText, "SECURITY ACTIVE");
    statusText.style.color = "#fff";
    hackerTextEffect(messageEl, "> SCANNING FACE FOR ACCESS...");
    lockIcon.className = "fa-solid fa-lock";
    lockIcon.style.color = "var(--neon-green)";
    laser.style.display = "block";

    btnEnroll.style.display = "none";

    btnDelete.style.display = "block";
    btnDelete.innerHTML = '<span class="btn-content">XÓA DỮ LIỆU GỐC</span>';
  } else if (mode === "RESET_CHECK") {
    hackerTextEffect(statusText, "SECURITY ALERT");
    statusText.style.color = ALERT_COLOR;
    hackerTextEffect(messageEl, "> ADMIN FACE REQUIRED TO DELETE");
    lockIcon.className = "fa-solid fa-skull";
    lockIcon.style.color = ALERT_COLOR;
    laser.style.display = "block";

    btnEnroll.style.display = "none";

    btnDelete.style.display = "block";
    btnDelete.innerHTML = '<span class="btn-content">HỦY THAO TÁC</span>';
  }
}

function startEnrollment() {
  if (currentMode === "IDLE") setMode("ENROLL");
  else setMode("IDLE");
}

function triggerResetSequence() {
  if (currentMode === "RESET_CHECK") {
    setMode("CHECK");
    return;
  }

  if (!faceMatcher) {
    alert("Chưa có dữ liệu trên Server để xóa!");
    return;
  }

  setMode("RESET_CHECK");
}

const SAFE_ZONE = {
  xMin: 0.3,
  yMin: 0.2,
  xMax: 0.7,
  yMax: 0.8,
  minSize: 0.25,
};

function showGuidance(text, color = "#ffd700") {
  if (guideEl && guideEl.innerText !== text) {
    guideEl.innerText = text;
    guideEl.style.borderColor = color;
    guideEl.style.color = color;
    guideEl.classList.add("guide-active");
  }
}

function hideGuidance() {
  if (guideEl && guideEl.classList.contains("guide-active")) {
    guideEl.classList.remove("guide-active");
    guideEl.innerText = "";
  }
}

function getGuidanceMessage(box, imgWidth, imgHeight) {
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;
  if (box.width < imgWidth * SAFE_ZONE.minSize) return "TIẾN LẠI GẦN HƠN ⚠️";
  if (cx < imgWidth * SAFE_ZONE.xMin) return "DỊCH SANG PHẢI >>";
  if (cx > imgWidth * SAFE_ZONE.xMax) return "<< DỊCH SANG TRÁI";
  if (cy < imgHeight * SAFE_ZONE.yMin) return "HẠ THẤP ĐẦU XUỐNG ▼";
  if (cy > imgHeight * SAFE_ZONE.yMax) return "NGẨNG CAO ĐẦU LÊN ▲";
  return "OK";
}

async function processFaceLogic() {
  if (isProcessingFace || isSaving || isSuccessLocked) return;

  isProcessingFace = true;
  try {
    const options = new faceapi.TinyFaceDetectorOptions({
      inputSize: 320,
      scoreThreshold: 0.5,
    });

    const detection = await faceapi
      .detectSingleFace(videoElement, options)
      .withFaceLandmarks()
      .withFaceDescriptor();

    if (!detection) {
      matchCounter = 0;
      if (currentMode !== "IDLE" && currentMode !== "UNLOCKED") {
      } else hideGuidance();
      isProcessingFace = false;
      return;
    }

    const box = detection.detection.box;
    const imgWidth = detection.detection.imageWidth;
    const imgHeight = detection.detection.imageHeight;
    const guidanceMsg = getGuidanceMessage(box, imgWidth, imgHeight);

    if (guidanceMsg !== "OK") {
      matchCounter = 0;
      showGuidance(guidanceMsg);
      drawGuidanceBox(box, false);
      isProcessingFace = false;
      return;
    } else {
      hideGuidance();
      drawGuidanceBox(box, true, matchCounter > 0 ? "#00ff00" : THEME_COLOR);
    }

    const descriptor = detection.descriptor;

    if (currentMode === "ENROLL") {
      const count = enrollDescriptors.length;
      const progress = (count / TARGET_SAMPLES) * 100;
      let instruction = "GIỮ NGUYÊN...";
      if (progress < 25) instruction = "NHÌN THẲNG (1/4)";
      else if (progress < 50) instruction = "NGHIÊNG TRÁI NHẸ (2/4)";
      else if (progress < 75) instruction = "NGHIÊNG PHẢI NHẸ (3/4)";
      else instruction = "NGƯỚC LÊN (4/4)";

      if (!messageEl.innerText.includes(instruction)) {
        hackerTextEffect(messageEl, "> " + instruction);
      }
      enrollDescriptors.push(descriptor);
      progressBar.style.width = progress + "%";
      drawLoadingCircle(box, progress);

      if (enrollDescriptors.length >= TARGET_SAMPLES && !isSaving) saveUser();
    } else if (currentMode === "CHECK" || currentMode === "RESET_CHECK") {
      if (!faceMatcher) {
        checkServerData();
        isProcessingFace = false;
        return;
      }

      const match = faceMatcher.findBestMatch(descriptor);

      if (match.label === "Admin" && match.distance < UNLOCK_THRESHOLD) {
        if (currentMode === "RESET_CHECK") {
          performReset();
        } else {
          matchCounter++;
          const percent = Math.min(
            (matchCounter / REQUIRED_MATCHES) * 100,
            100
          );

          showGuidance(`GIỮ NGUYÊN... ${Math.floor(percent)}%`, "#00f3ff");
          drawLoadingCircle(box, percent);

          if (matchCounter >= REQUIRED_MATCHES) {
            hideGuidance();
            handleLoginSuccess();
          }
        }
      } else {
        matchCounter = 0;
        if (match.label === "Admin") {
          showGuidance("ĐỘ KHỚP THẤP - CHỈNH LẠI KÍNH/GÓC MẶT", "#ffaa00");
        } else {
          hackerTextEffect(messageEl, "> TỪ CHỐI: KHÔNG PHẢI ADMIN");
        }
      }
    }
  } catch (e) {
    console.error(e);
  }
  isProcessingFace = false;
}

function handleLoginSuccess() {
  if (isSuccessLocked) return;
  isSuccessLocked = true;

  scanStatusOverlay.classList.add("success-flash");
  terminalContainer.classList.add("access-granted");
  videoMask.classList.add("success-border");

  lockIcon.className = "fa-solid fa-unlock";
  lockIcon.style.color = "#00ff00";
  hackerTextEffect(statusText, "ACCESS GRANTED");
  statusText.style.color = "#00ff00";
  hackerTextEffect(messageEl, "> IDENTITY CONFIRMED. REDIRECTING...");

  setTimeout(() => {
    sessionStorage.setItem("legacyFaceRedirectDisabled", "1");
    window.location.href = "index.html";
  }, 500);
}

function drawGuidanceBox(box, isSafe, colorOverride = null) {
  const color = colorOverride
    ? colorOverride
    : isSafe
      ? THEME_COLOR
      : ALERT_COLOR;

  ctxOverlay.strokeStyle = color;
  ctxOverlay.lineWidth = 2;
  ctxOverlay.lineCap = "round";
  ctxOverlay.lineJoin = "round";

  ctxOverlay.shadowColor = color;
  ctxOverlay.shadowBlur = 10;

  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  const radiusX = box.width * 0.6;
  const radiusY = box.height * 0.75;

  const segments = 40;
  const step = (Math.PI * 2) / segments;

  ctxOverlay.beginPath();
  for (let i = 0; i <= segments; i++) {
    const angle = i * step - Math.PI / 2;

    const px = cx + radiusX * Math.cos(angle);
    const py = cy + radiusY * Math.sin(angle);

    if (i === 0) {
      ctxOverlay.moveTo(px, py);
    } else {
      ctxOverlay.lineTo(px, py);
    }
  }
  ctxOverlay.closePath();
  ctxOverlay.stroke();

  ctxOverlay.shadowBlur = 0;

  if (!isSafe) {
    ctxOverlay.beginPath();
    ctxOverlay.lineWidth = 1;
    ctxOverlay.globalAlpha = 0.5;

    const triY = cy + radiusY * 0.2;
    ctxOverlay.moveTo(cx, cy);
    ctxOverlay.lineTo(cx - box.width * 0.3, triY + box.height * 0.3);
    ctxOverlay.lineTo(cx + box.width * 0.3, triY + box.height * 0.3);
    ctxOverlay.lineTo(cx, cy);
    ctxOverlay.stroke();
    ctxOverlay.globalAlpha = 1.0;
  }
}

async function saveUser() {
  if (isSaving) return;
  isSaving = true;
  laser.style.display = "none";
  hackerTextEffect(messageEl, "> WRITING FACE VECTORS TO MONGODB...");

  try {
    const optimized = enrollDescriptors
      .filter((_, i) => i % 2 === 0)
      .map((d) => Array.from(d));

    const res = await fetch(`${API_URL}/face-id/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: "Admin",
        descriptors: optimized,
      }),
    });

    const json = await res.json();

    if (json.success) {
      const user = { label: "Admin", descriptors: optimized };
      loadMatcher([user]);

      setTimeout(() => {
        hackerTextEffect(messageEl, "> UPLOAD COMPLETE. SYSTEM LOCKED.");
        setTimeout(() => {
          setMode("CHECK");
        }, 1000);
      }, 1000);
    } else {
      throw new Error(json.message);
    }
  } catch (e) {
    console.error(e);
    const msg = String(e?.message || "");
    if (msg.includes("FACE_STORE_UNAVAILABLE")) {
      hackerTextEffect(messageEl, "> MONGODB OFFLINE. SAVE BLOCKED.");
    } else {
      hackerTextEffect(messageEl, "> SAVE FAILED! TRY AGAIN.");
    }
    isSaving = false;
    setTimeout(() => setMode("IDLE"), 2000);
  }
}

async function performReset() {
  hackerTextEffect(statusText, "DELETING SERVER DATA...");
  hackerTextEffect(messageEl, "> REQUESTING PURGE...");

  try {
    const res = await fetch(`${API_URL}/face-id/clear`, { method: "DELETE" });
    const json = await res.json();

    if (json.success) {
      hackerTextEffect(messageEl, "> DATABASE PURGED.");
      setTimeout(() => {
        location.reload();
      }, 2000);
    }
  } catch (e) {
    const msg = String(e?.message || "");
    alert(msg.includes("FACE_STORE_UNAVAILABLE") ? "MongoDB chưa sẵn sàng nên chưa thể xóa FaceID." : "Lỗi kết nối Server không thể xóa!");
    location.reload();
  }
}

function loadMatcher(data) {
  const labeledDescriptors = data.map(
    (u) =>
      new faceapi.LabeledFaceDescriptors(
        u.label,
        u.descriptors.map((d) => new Float32Array(d))
      )
  );
  faceMatcher = new faceapi.FaceMatcher(labeledDescriptors, UNLOCK_THRESHOLD);
}

function onFaceMeshResults(results) {
  canvasOverlay.width = videoElement.videoWidth;
  canvasOverlay.height = videoElement.videoHeight;

  ctxOverlay.save();
  ctxOverlay.clearRect(0, 0, canvasOverlay.width, canvasOverlay.height);

  // Vẽ lưới mặt xanh giống kiểu FaceMesh (như ảnh bạn gửi)
  if (results.multiFaceLandmarks && results.multiFaceLandmarks.length > 0 && !isSuccessLocked) {
    const landmarks = results.multiFaceLandmarks[0];

    // Glow nhẹ
    ctxOverlay.shadowBlur = 12;
    ctxOverlay.shadowColor = "#00ff00";

    // Lưới tam giác phủ toàn mặt
    drawConnectors(ctxOverlay, landmarks, FACEMESH_TESSELATION, {
      color: "#00ff00",
      lineWidth: 1,
    });

    // Viền mặt/mắt/môi cho rõ hơn
    drawConnectors(ctxOverlay, landmarks, FACEMESH_CONTOURS, {
      color: "#00ff00",
      lineWidth: 2,
    });

    ctxOverlay.shadowBlur = 0;
  }

  const now = Date.now();
  if (now - lastFaceCheckTime > 200 && isSystemReady) {
    processFaceLogic();
    lastFaceCheckTime = now;
  }

  ctxOverlay.restore();
}


function drawCyberpunkVisuals(landmarks) {
  const isAlert =
    currentMode === "RESET_CHECK" ||
    (currentMode === "CHECK" && messageEl.innerText.includes("DENIED"));

  const color =
    matchCounter > 0 ? SUCCESS_COLOR : isAlert ? ALERT_COLOR : THEME_COLOR;

  const w = canvasOverlay.width;
  const h = canvasOverlay.height;

  ctxOverlay.strokeStyle = color;
  ctxOverlay.fillStyle = color;
  ctxOverlay.lineCap = "round";
  ctxOverlay.shadowColor = color;

  const drawLine = (i, j) => {
    const p1 = landmarks[i];
    const p2 = landmarks[j];
    if (p1.visibility > 0.5 && p2.visibility > 0.5) {
      ctxOverlay.beginPath();
      ctxOverlay.moveTo(p1.x * w, p1.y * h);
      ctxOverlay.lineTo(p2.x * w, p2.y * h);
      ctxOverlay.stroke();
    }
  };

  const nose = landmarks[0];
  const ear = landmarks[7];
  if (nose.visibility > 0.5 && ear.visibility > 0.5) {
    ctxOverlay.beginPath();
    const r = Math.hypot((ear.x - nose.x) * w, (ear.y - nose.y) * h) * 2.2;
    ctxOverlay.arc(nose.x * w, nose.y * h, r, 0, 2 * Math.PI);
    ctxOverlay.lineWidth = 2;
    ctxOverlay.shadowBlur = GLOW_AMOUNT;
    ctxOverlay.stroke();
  }

  ctxOverlay.lineWidth = 1;
  [
    [7, 2],
    [8, 5],
    [2, 0],
    [5, 0],
    [2, 9],
    [5, 10],
    [0, 9],
    [0, 10],
    [9, 10],
    [2, 5],
  ].forEach((p) => drawLine(p[0], p[1]));

  ctxOverlay.lineWidth = LINE_WIDTH;
  drawLine(9, 11);
  drawLine(10, 12);
  [
    [11, 12],
    [11, 13],
    [13, 15],
    [12, 14],
    [14, 16],
    [11, 23],
    [12, 24],
    [23, 24],
  ].forEach((p) => drawLine(p[0], p[1]));
}

function drawLoadingCircle(box, percent) {
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;
  ctxOverlay.beginPath();
  ctxOverlay.arc(
    cx,
    cy,
    box.width / 1.5,
    -Math.PI / 2,
    -Math.PI / 2 + Math.PI * 2 * (percent / 100)
  );
  ctxOverlay.lineWidth = 5;
  ctxOverlay.strokeStyle = matchCounter > 0 ? SUCCESS_COLOR : THEME_COLOR;
  ctxOverlay.stroke();
}

function showWelcomeScreen() {
  currentMode = "UNLOCKED";
  document.getElementById("main-terminal").classList.add("hidden");
  document.getElementById("welcome-screen").classList.remove("hidden");
}

function logoutSystem() {
  isSuccessLocked = false;
  scanStatusOverlay.classList.remove("success-flash");
  terminalContainer.classList.remove("access-granted");
  videoMask.classList.remove("success-border");
  lockIcon.className = "fa-solid fa-lock";
  lockIcon.style.color = "var(--neon-green)";

  document.getElementById("welcome-screen").classList.add("hidden");
  document.getElementById("main-terminal").classList.remove("hidden");
  setMode("CHECK");
}

function startCameraPipeline() {
  const faceMesh = new FaceMesh({
    locateFile: (file) => `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh/${file}`,
  });

  faceMesh.setOptions({
    maxNumFaces: 1,
    refineLandmarks: true,
    minDetectionConfidence: 0.5,
    minTrackingConfidence: 0.5,
  });

  faceMesh.onResults(onFaceMeshResults);

  const camera = new Camera(videoElement, {
    onFrame: async () => {
      await faceMesh.send({ image: videoElement });
    },
    width: 640,
    height: 480,
  });

  camera.start();
}


(function () {
  const BASE_SPEED_ONG = 1.3,
    BASE_SPEED_BUOM = 1.5;
  const ONG_SIZE = 280,
    BUOM_SIZE = 170;
  const RESCUE_PROBABILITY = 0.25;

  let lastInteractTime = 0,
    lastRescueTime = 0,
    lastProjectileTime = 0;
  let togetherTime = 0,
    captureCount = 0;

  const MOOD_LINES = {
    HAPPY: [
      "Đời tươi đẹp quá!",
      "Yêu em Bướm nhất!",
      "Phưng Tướn đang vui!",
      "Hôm nay Cloud mượt ghê!",
      "Bay lượn là đam mê!",
    ],
    ANGRY: [
      "Đừng chạm vào tao!",
      "Admin làm ăn kiểu gì đấy?",
      "Đang bực nhé!",
      "Đốt cho phát giờ!",
      "Cút ra chỗ khác!",
      "Phá đám vừa thôi!",
    ],
    HUNGRY: [
      "Đói quá, có gì ăn k?",
      "Hút mật thôi em ơi!",
      "Mật hoa Cloud ngon k nhỉ?",
      "Hết năng lượng rồi...",
      "Kiếm gì bỏ bụng đi!",
    ],
    CRAZY: [
      "QUẨY LÊN!",
      "BAY XUYÊN MÀN HÌNH!",
      "TỐC ĐỘ BÀN THỜ!",
      "Ú òa!",
      "Ahihi đồ ngốc!",
      "Đố bắt được đấy!",
    ],
    NIGHT: [
      "Gần đêm rồi, chưa ngủ à?",
      "Đi quẩy đêm thôi em!",
      "Admin thức khuya thế?",
      "Ngủ ngon nha cả nhà!",
      "Mắt sắp díp lại rồi...",
    ],
    SCAN: [
      "Scan gì đấy? Scan anh này!",
      "Face ID của em là hình anh!",
      "Đừng nhìn camera, nhìn anh nè!",
      "Anh đẹp trai thế này máy k nhận à?",
    ],
  };

  const RAW_LINES = {
    captured_ong: [
      "ĐM buông tao ra!!",
      "Bớ người ta hiếp ong!",
      "Mày biết bố mày là ai không?",
      "Thả ra thằng Admin kia!",
      "Bố mày ghim rồi đấy!",
      "Đồ phá đám!",
    ],
    captured_buom: [
      "Cứu em anh Ong ơi!",
      "Admin dê xồm!",
      "Áaaa thả ra!",
      "Hỏng hết nhan sắc rồi!",
      "Anh hùng Ong đâu rồi?",
    ],
    mock_buom: [
      "Lêu lêu đáng đời béo!",
      "Cho chừa tội bám đuôi!",
      "Hi hi Admin làm tốt lắm!",
      "Đáng đời chưa!",
      "Bay hộ cái!",
    ],
    hero: [
      "THẢ VỢ TAO RA!!!",
      "CHẾT NÈ THẰNG KIA!",
      "DÁM ĐỘNG VÀO NÀNG À?",
      "ÔNG TỚI ĐÂY!",
      "ĐM ADMIN DỪNG TAY!",
    ],
    victory: [
      "Tuổi gì bắt được bọn anh!",
      "Chạy mau em ơi!",
      "Admin gà vãi!",
      "Anh hùng cứu mĩ nhân!",
    ],
    thanks: ["Yêu anh nhất!", "Anh hùng của em!", "Suýt thì tiêu đời!"],
    interaction: [
      "Đá đít cái nè!",
      "Xoay vòng vòng đi em!",
      "Tàng hình nè!",
      "Đố tìm thấy em!",
    ],
  };

  const LineManager = {
    used: new Set(),
    get(category) {
      let pool = MOOD_LINES[category] || RAW_LINES[category];
      let available = pool.filter((line) => !this.used.has(line));
      if (available.length === 0) {
        this.used.clear();
        available = pool;
      }
      let picked = available[Math.floor(Math.random() * available.length)];
      this.used.add(picked);
      return picked;
    },
  };

  function launchProjectile(fromX, fromY, toX, toY) {
    if (Date.now() - lastProjectileTime < 1000) return;
    lastProjectileTime = Date.now();
    const p = document.createElement("div");
    p.innerText = Math.random() > 0.5 ? "💩" : "🔥";
    p.style.cssText = `position:fixed; z-index:20005; left:${fromX}px; top:${fromY}px; font-size:35px; transition: all 0.5s ease-in; pointer-events:none;`;
    document.body.appendChild(p);
    setTimeout(() => {
      p.style.left = toX + "px";
      p.style.top = toY + "px";
      p.style.transform = "rotate(360deg) scale(1.5)";
    }, 20);
    setTimeout(() => {
      document.body.style.filter = "invert(0.1) brightness(1.2)";
      setTimeout(() => {
        document.body.style.filter = "none";
        p.remove();
      }, 100);
    }, 500);
  }

  function createSpeechBox(color = "#000") {
    const box = document.createElement("div");
    Object.assign(box.style, {
      backgroundColor: "rgba(255, 255, 255, 0.98)",
      border: "2px solid #000",
      borderRadius: "8px",
      padding: "4px 8px",
      fontSize: "13px",
      fontWeight: "900",
      marginBottom: "-75px",
      opacity: "0",
      transition: "all 0.2s",
      boxShadow: "2px 2px 0px #000",
      fontFamily: "monospace",
      zIndex: "20002",
      color: color,
      whiteSpace: "nowrap",
      pointerEvents: "none",
    });
    return box;
  }

  class Character {
    constructor(id, imgSrc, size, baseSpeed) {
      this.id = id;
      this.size = size;
      this.baseSpeed = baseSpeed;
      this.container = document.createElement("div");
      Object.assign(this.container.style, {
        position: "fixed",
        zIndex: "20001",
        pointerEvents: "auto",
        left: "50px",
        top: "50px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        cursor: "grab",
      });
      this.speechBox = createSpeechBox(id === "ong" ? "#d63031" : "#e84393");
      this.container.appendChild(this.speechBox);
      this.img = document.createElement("img");
      this.img.src = imgSrc;
      this.img.style.width = `${size}px`;
      this.img.style.userSelect = "none";
      this.img.draggable = false;
      this.container.appendChild(this.img);
      document.body.appendChild(this.container);

      this.x = Math.random() * window.innerWidth;
      this.y = Math.random() * window.innerHeight;
      this.angle = Math.random() * Math.PI * 2;
      this.currentSpeed = baseSpeed;
      this.isCaptured = false;
      this.isEvolved = false;
      this.mood = "HAPPY";
      this.moodTimer = 0;

      this.container.addEventListener("mousedown", (e) => {
        e.preventDefault();
        this.isCaptured = true;
        this.img.style.filter = "sepia(1) saturate(5) contrast(1.2)";
        this.say(
          LineManager.get(this.id === "ong" ? "captured_ong" : "captured_buom")
        );
        captureCount++;
      });
      window.addEventListener("mouseup", () => this.forceRelease());
    }

    forceRelease() {
      if (this.isCaptured) {
        this.isCaptured = false;
        this.img.style.filter = this.isEvolved ? this.img.style.filter : "none";
        this.currentSpeed = this.baseSpeed;
        document.body.style.backgroundColor = "";
        this.mood = "ANGRY";
        this.moodTimer = 200;
      }
    }

    say(msg, time = 2500) {
      this.speechBox.innerText = msg;
      this.speechBox.style.opacity = "1";
      setTimeout(() => (this.speechBox.style.opacity = "0"), time);
    }

    update(partner) {
      const now = Date.now();
      if (this.isCaptured) {
        document.body.style.backgroundColor = "rgba(0,0,0,0.15)";
        const shake = (Math.random() - 0.5) * 15;
        this.container.style.transform = `translate(${this.x + shake}px, ${this.y + shake
          }px) scale(0.85)`;
        return;
      }

      this.moodTimer--;
      if (this.moodTimer <= 0) {
        const hour = new Date().getHours();
        if (hour >= 22 || hour <= 5) this.mood = "NIGHT";
        else if (window.location.href.includes("face")) this.mood = "SCAN";
        else {
          const moods = ["HAPPY", "HAPPY", "HUNGRY", "CRAZY"];
          this.mood = moods[Math.floor(Math.random() * moods.length)];
        }
        this.moodTimer = 400 + Math.random() * 400;
        if (Math.random() < 0.2) this.say(LineManager.get(this.mood));
      }

      let multiplier = 1;
      if (this.mood === "CRAZY") multiplier = 2.4;
      if (this.mood === "HUNGRY") multiplier = 0.6;
      if (this.mood === "ANGRY") multiplier = 1.8;

      if (partner.isCaptured) {
        const dx = partner.x + partner.size / 2 - (this.x + this.size / 2);
        const dy = partner.y + partner.size / 2 - (this.y + this.size / 2);
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (this.id === "ong") {
          this.angle = Math.atan2(dy, dx);
          this.currentSpeed = 12;
          if (dist < 350)
            launchProjectile(
              this.x + 140,
              this.y + 100,
              partner.x + 85,
              partner.y + 85
            );
          if (dist < 130 && now - lastRescueTime > 1200) {
            lastRescueTime = now;
            if (Math.random() < RESCUE_PROBABILITY) {
              partner.forceRelease();
              this.say(LineManager.get("victory"));
              partner.say(LineManager.get("thanks"));
              this.angle += Math.PI;
              this.currentSpeed = 20;
            } else {
              this.say(LineManager.get("hero"));
            }
          }
        } else {
          this.angle += 0.2;
          this.x = partner.x + Math.cos(this.angle) * 180;
          this.y = partner.y + Math.sin(this.angle) * 180;
          if (Math.random() < 0.01) this.say(LineManager.get("mock_buom"));
          this.container.style.transform = `translate(${this.x}px, ${this.y}px)`;
          return;
        }
      } else {
        this.angle += (Math.random() - 0.5) * 0.25;
        this.currentSpeed =
          (this.isEvolved ? this.baseSpeed * 2.2 : this.baseSpeed) * multiplier;
      }

      this.x += Math.cos(this.angle) * this.currentSpeed;
      this.y += Math.sin(this.angle) * this.currentSpeed;

      const pad = 30;
      if (this.x < -pad) {
        this.x = -pad;
        this.angle = 0;
      }
      if (this.x > window.innerWidth - this.size + pad) {
        this.x = window.innerWidth - this.size + pad;
        this.angle = Math.PI;
      }
      if (this.y < -pad) {
        this.y = -pad;
        this.angle = Math.PI / 2;
      }
      if (this.y > window.innerHeight - this.size + pad) {
        this.y = window.innerHeight - this.size + pad;
        this.angle = -Math.PI / 2;
      }

      this.img.style.transform =
        Math.cos(this.angle) < 0 ? "scaleX(1)" : "scaleX(-1)";
      this.container.style.transform = `translate(${this.x}px, ${this.y}px)`;
    }
  }

  const ong = new Character(
    "ong",
    "https://cdn.pixabay.com/animation/2024/04/25/19/52/19-52-51-662_512.gif",
    ONG_SIZE,
    1.3
  );
  const buom = new Character(
    "buom",
    "https://cdn.pixabay.com/animation/2025/10/17/17/13/17-13-24-511_512.gif",
    BUOM_SIZE,
    1.5
  );

  function loop() {
    ong.update(buom);
    buom.update(ong);
    const dist = Math.sqrt(
      Math.pow(buom.x - ong.x, 2) + Math.pow(buom.y - ong.y, 2)
    );

    if (dist < 150 && !ong.isCaptured && !buom.isCaptured) {
      togetherTime++;
      if (togetherTime > 300) {
        ong.isEvolved = true;
        buom.isEvolved = true;
        ong.img.style.filter = "drop-shadow(0 0 15px gold)";
        buom.img.style.filter = "drop-shadow(0 0 15px pink)";
      }
      if (Math.random() < 0.005) {
        const act = Math.random();
        if (act < 0.5) {
          buom.img.style.opacity = "0";
          setTimeout(() => (buom.img.style.opacity = "1"), 2000);
          buom.say("Tàng hình nè!");
        } else {
          ong.say("Đá đít nè!");
          buom.angle += Math.PI;
        }
      }
    } else {
      togetherTime = 0;
      ong.isEvolved = false;
      buom.isEvolved = false;
    }
    requestAnimationFrame(loop);
  }
  loop();

  window.addEventListener("resize", () => {
    ong.x = Math.min(ong.x, window.innerWidth - 100);
    buom.x = Math.min(buom.x, window.innerWidth - 100);
  });
})();

initSystem();

// ===== Security hardening patch (preserve original UI/animations) =====
try {
  localStorage.removeItem("faceAuthSuccess");
  localStorage.removeItem("realAdminPass");
  sessionStorage.removeItem("adminToken");
} catch (_) { }

let serverFaceEnabled = false;
let serverVerifyInFlight = false;
let lastServerVerifyAt = 0;
const SERVER_REQUIRED_MATCHES = 4;
const SERVER_VERIFY_INTERVAL_MS = 450;

async function getAdminSessionState() {
  try {
    const res = await fetch(`${API_URL}/admin/session`, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    return await res.json();
  } catch (_) {
    return { authenticated: false };
  }
}

async function ensureAdminSessionForFaceSetup() {
  const session = await getAdminSessionState();
  if (session && session.authenticated) return true;

  const pass = window.prompt("Nhập mật khẩu Admin để thiết lập Face ID:");
  if (!pass) return false;

  const res = await fetch(`${API_URL}/admin/login`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: pass }),
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.success) {
    hackerTextEffect(messageEl, "> ADMIN AUTH FAILED.");
    return false;
  }

  return true;
}

async function checkServerData() {
  hackerTextEffect(messageEl, "> SYNCING WITH MONGODB...");
  try {
    const res = await fetch(`${API_URL}/face-id/status`, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    const json = await res.json();

    if (!res.ok || json.available === false) {
      serverFaceEnabled = false;
      faceMatcher = null;
      setMode("IDLE");
      hackerTextEffect(messageEl, "> MONGODB OFFLINE. FACE VAULT LOCKED.");
      return;
    }

    serverFaceEnabled = !!json.hasFace;
    faceMatcher = serverFaceEnabled ? { label: "Admin" } : null;

    if (serverFaceEnabled) {
      setMode("CHECK");
      hackerTextEffect(messageEl, "> DATA SYNCED. MONGODB ARMED.");
    } else {
      setMode("IDLE");
      hackerTextEffect(messageEl, "> NO FACE DATA IN MONGODB.");
    }
  } catch (e) {
    console.error("Lỗi tải Face ID:", e);
    serverFaceEnabled = false;
    faceMatcher = null;
    hackerTextEffect(messageEl, "> SERVER ERROR. MONGODB OFFLINE.");
    setMode("IDLE");
  }
}

async function verifyDescriptorWithServer(descriptor, intent = "login") {
  const res = await fetch(`${API_URL}/face-id/verify`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      intent,
      descriptor: Array.from(descriptor || []),
    }),
  });

  const json = await res.json().catch(() => ({}));
  return {
    ok: !!(res.ok && json.success && json.verified),
    status: res.status,
    data: json,
  };
}

async function processFaceLogic() {
  if (isProcessingFace || isSaving || isSuccessLocked) return;

  isProcessingFace = true;
  try {
    const options = new faceapi.TinyFaceDetectorOptions({
      inputSize: 320,
      scoreThreshold: 0.5,
    });

    const detection = await faceapi
      .detectSingleFace(videoElement, options)
      .withFaceLandmarks()
      .withFaceDescriptor();

    if (!detection) {
      matchCounter = 0;
      hideGuidance();
      isProcessingFace = false;
      return;
    }

    const box = detection.detection.box;
    const imgWidth = detection.detection.imageWidth;
    const imgHeight = detection.detection.imageHeight;
    const guidanceMsg = getGuidanceMessage(box, imgWidth, imgHeight);

    if (guidanceMsg !== "OK") {
      matchCounter = 0;
      showGuidance(guidanceMsg);
      drawGuidanceBox(box, false);
      isProcessingFace = false;
      return;
    }

    hideGuidance();
    drawGuidanceBox(box, true, matchCounter > 0 ? "#00ff00" : THEME_COLOR);

    const descriptor = detection.descriptor;

    if (currentMode === "ENROLL") {
      const count = enrollDescriptors.length;
      const progress = (count / TARGET_SAMPLES) * 100;
      let instruction = "GIỮ NGUYÊN...";
      if (progress < 25) instruction = "NHÌN THẲNG (1/4)";
      else if (progress < 50) instruction = "NGHIÊNG TRÁI NHẸ (2/4)";
      else if (progress < 75) instruction = "NGHIÊNG PHẢI NHẸ (3/4)";
      else instruction = "NGƯỚC LÊN (4/4)";

      if (!messageEl.innerText.includes(instruction)) {
        hackerTextEffect(messageEl, "> " + instruction);
      }

      enrollDescriptors.push(descriptor);
      progressBar.style.width = progress + "%";
      drawLoadingCircle(box, progress);

      if (enrollDescriptors.length >= TARGET_SAMPLES && !isSaving) {
        await saveUser();
      }

      isProcessingFace = false;
      return;
    }

    if (currentMode !== "CHECK" && currentMode !== "RESET_CHECK") {
      isProcessingFace = false;
      return;
    }

    if (!serverFaceEnabled) {
      await checkServerData();
      isProcessingFace = false;
      return;
    }

    const now = Date.now();
    const percent = Math.min((matchCounter / SERVER_REQUIRED_MATCHES) * 100, 100);
    if (matchCounter > 0) {
      showGuidance(`GIỮ NGUYÊN... ${Math.floor(percent)}%`, "#00f3ff");
      drawLoadingCircle(box, percent);
    }

    if (serverVerifyInFlight || now - lastServerVerifyAt < SERVER_VERIFY_INTERVAL_MS) {
      isProcessingFace = false;
      return;
    }

    serverVerifyInFlight = true;
    lastServerVerifyAt = now;

    const verify = await verifyDescriptorWithServer(
      descriptor,
      currentMode === "RESET_CHECK" ? "reset" : "login"
    );

    serverVerifyInFlight = false;

    if (verify.ok) {
      matchCounter++;
      const nextPercent = Math.min(
        (matchCounter / SERVER_REQUIRED_MATCHES) * 100,
        100
      );
      showGuidance(`GIỮ NGUYÊN... ${Math.floor(nextPercent)}%`, "#00f3ff");
      drawLoadingCircle(box, nextPercent);

      if (matchCounter >= SERVER_REQUIRED_MATCHES) {
        hideGuidance();
        if (currentMode === "RESET_CHECK") {
          await performReset();
        } else {
          handleLoginSuccess();
        }
      }
    } else {
      matchCounter = 0;
      const reason = String(verify?.data?.message || "");
      if (reason.includes("NO_FACE_DATA")) {
        serverFaceEnabled = false;
        faceMatcher = null;
        setMode("IDLE");
      } else if (reason.includes("FACE_STORE_UNAVAILABLE")) {
        serverFaceEnabled = false;
        faceMatcher = null;
        hackerTextEffect(messageEl, "> MONGODB OFFLINE. VERIFY BLOCKED.");
        showGuidance("MONGODB OFFLINE", "#ffaa00");
        setMode("IDLE");
      } else if (reason.includes("INVALID_DESCRIPTOR")) {
        showGuidance("KHÔNG ĐỌC ĐƯỢC KHUÔN MẶT", "#ffaa00");
      } else {
        showGuidance("ĐỘ KHỚP THẤP - CHỈNH LẠI GÓC MẶT", "#ffaa00");
      }
    }
  } catch (e) {
    console.error(e);
  }
  isProcessingFace = false;
}

function handleLoginSuccess() {
  if (isSuccessLocked) return;
  isSuccessLocked = true;

  scanStatusOverlay.classList.add("success-flash");
  terminalContainer.classList.add("access-granted");
  videoMask.classList.add("success-border");

  lockIcon.className = "fa-solid fa-unlock";
  lockIcon.style.color = "#00ff00";
  hackerTextEffect(statusText, "ACCESS GRANTED");
  statusText.style.color = "#00ff00";
  hackerTextEffect(messageEl, "> IDENTITY CONFIRMED. REDIRECTING...");

  setTimeout(() => {
    window.location.href = "index.html?fromFace=1";
  }, 500);
}

async function saveUser() {
  if (isSaving) return;
  isSaving = true;
  laser.style.display = "none";
  hackerTextEffect(messageEl, "> WRITING FACE VECTORS TO MONGODB...");

  const sessionReady = await ensureAdminSessionForFaceSetup();
  if (!sessionReady) {
    isSaving = false;
    hackerTextEffect(messageEl, "> ADMIN AUTH REQUIRED.");
    setTimeout(() => setMode("IDLE"), 1200);
    return;
  }

  try {
    const optimized = enrollDescriptors
      .filter((_, i) => i % 2 === 0)
      .map((d) => Array.from(d));

    const res = await fetch(`${API_URL}/face-id/register`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: "Admin",
        descriptors: optimized,
      }),
    });

    const json = await res.json();

    if (res.ok && json.success) {
      serverFaceEnabled = true;
      faceMatcher = { label: "Admin" };

      setTimeout(() => {
        hackerTextEffect(messageEl, "> UPLOAD COMPLETE. SYSTEM LOCKED.");
        setTimeout(() => {
          setMode("CHECK");
        }, 1000);
      }, 1000);
    } else {
      throw new Error(json.message || "UPLOAD_FAILED");
    }
  } catch (e) {
    console.error(e);
    hackerTextEffect(messageEl, "> UPLOAD FAILED! TRY AGAIN.");
    isSaving = false;
    setTimeout(() => setMode("IDLE"), 2000);
  }
}

async function performReset() {
  hackerTextEffect(statusText, "DELETING SERVER DATA...");
  hackerTextEffect(messageEl, "> REQUESTING PURGE...");

  try {
    const res = await fetch(`${API_URL}/face-id/clear`, {
      method: "DELETE",
      credentials: "same-origin",
    });
    const json = await res.json();

    if (res.ok && json.success) {
      hackerTextEffect(messageEl, "> DATABASE PURGED.");
      setTimeout(() => {
        location.reload();
      }, 1200);
      return;
    }

    throw new Error(json.message || "RESET_FAILED");
  } catch (e) {
    alert("Lỗi kết nối Server không thể xóa!");
    location.reload();
  }
}

async function startEnrollment() {
  if (currentMode === "IDLE") {
    const ok = await ensureAdminSessionForFaceSetup();
    if (!ok) return;
    setMode("ENROLL");
  } else {
    setMode("IDLE");
  }
}

function triggerResetSequence() {
  if (currentMode === "RESET_CHECK") {
    setMode("CHECK");
    return;
  }

  if (!serverFaceEnabled) {
    alert("Chưa có dữ liệu Face ID trên Server để xóa!");
    return;
  }

  setMode("RESET_CHECK");
}

setTimeout(() => {
  checkServerData().catch(() => { });
}, 120);