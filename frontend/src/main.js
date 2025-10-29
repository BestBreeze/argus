// frontend/main.js
import './style.css';
import { SelectProject, ScanProject, OpenReportInBrowser } from '../wailsjs/go/main/App';
import { EventsOn } from '../wailsjs/runtime/runtime';

// --- DOM Elements ---
const app = document.getElementById('app');
app.innerHTML = `
    <div class="controls">
        <input id="project-path" type="text" placeholder="请选择项目文件夹..." readonly />
        <button id="select-btn">选择项目</button>
        <button id="scan-btn" disabled>开始扫描</button>
    </div>
    <div id="log-container">欢迎使用 Argus 安全扫描引擎！</div>
    <div id="result-link"></div>
`;

const projectPathInput = document.getElementById('project-path');
const selectBtn = document.getElementById('select-btn');
const scanBtn = document.getElementById('scan-btn');
const logContainer = document.getElementById('log-container');
const resultLinkContainer = document.getElementById('result-link');

let reportPath = '';

// --- Event Listeners ---
selectBtn.addEventListener('click', () => {
    SelectProject().then(path => {
        if (path) {
            projectPathInput.value = path;
            scanBtn.disabled = false;
        }
    }).catch(err => {
        appendLog('错误: ' + err, 'error');
    });
});

scanBtn.addEventListener('click', () => {
    const path = projectPathInput.value;
    if (!path) return;

    // 禁用按钮，清空日志
    setScanningState(true);
    
    // 调用Go后端的扫描方法
    ScanProject(path).then(resPath => {
        reportPath = resPath;
        showResultLink();
    }).catch(err => {
        appendLog('扫描失败: ' + err, 'error');
    }).finally(() => {
        setScanningState(false);
    });
});

// 监听Go后端发送的日志事件
EventsOn('log', (message) => {
    appendLog(message);
});

// --- Helper Functions ---
function appendLog(message, type = 'info') {
    const p = document.createElement('p');
    p.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    if (type === 'error') {
        p.style.color = '#e74c3c';
    }
    logContainer.appendChild(p);
    logContainer.scrollTop = logContainer.scrollHeight; // 自动滚动到底部
}

function setScanningState(isScanning) {
    if (isScanning) {
        selectBtn.disabled = true;
        scanBtn.disabled = true;
        scanBtn.innerText = '扫描中...';
        logContainer.innerHTML = '';
        resultLinkContainer.innerHTML = '';
        reportPath = '';
    } else {
        selectBtn.disabled = false;
        scanBtn.disabled = false;
        scanBtn.innerText = '开始扫描';
    }
}

function showResultLink() {
    if (!reportPath) return;
    
    const resultButton = document.createElement('button');
    resultButton.innerText = '🎉 扫描完成！点击查看报告';
    resultButton.id = 'report-btn'; // 给它一个ID，方便应用样式
    
    resultButton.addEventListener('click', (e) => {
        e.preventDefault();
        // 调用Go后端方法，在浏览器中打开报告
        OpenReportInBrowser(reportPath);
    });
    
    resultLinkContainer.appendChild(resultButton);
}