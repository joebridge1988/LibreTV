// 导入 SHA-256 哈希函数
// 假设此文件 (sha256.js) 提供了全局的 sha256 函数或通过模块导出
// 如果 sha256 函数在当前文件中定义，则无需此导入
// import { sha256 } from '../js/sha256.js'; // 原始文件中有此行，保留

// 假设 PASSWORD_CONFIG 在其他地方定义并可用，例如：
const PASSWORD_CONFIG = {
    localStorageKey: 'password_verified',
    adminLocalStorageKey: 'admin_password_verified',
    verificationTTL: 24 * 60 * 60 * 1000 // 验证有效期，例如 1 天
};

// 密码保护功能

/**
 * 检查是否设置了密码保护
 * 通过读取页面上嵌入的环境变量来检查
 */
function isPasswordProtected() {
    // 检查页面上嵌入的环境变量
    const username = window.__ENV__ && window.__ENV__.USERNAME; // 新增：获取用户名
    const pwd = window.__ENV__ && window.__ENV__.PASSWORD;
    const adminPwd = window.__ENV__ && window.__ENV__.ADMINPASSWORD;

    // 检查用户名是否有效（非空字符串）
    const isUsernameValid = typeof username === 'string' && username.length > 0;
    // 检查普通密码或管理员密码是否有效（哈希值长度为 64 且不全为 0）
    const isPwdValid = typeof pwd === 'string' && pwd.length === 64 && !/^0+$/.test(pwd);
    const isAdminPwdValid = typeof adminPwd === 'string' && adminPwd.length === 64 && !/^0+$/.test(adminPwd);

    // 只有当设置了用户名，并且普通密码或管理员密码有效时，才认为启用了密码保护
    return isUsernameValid && (isPwdValid || isAdminPwdValid);
}

window.isPasswordProtected = isPasswordProtected;

/**
 * 验证用户输入的用户名和密码是否正确（异步，使用SHA-256哈希）
 * @param {string} username 用户输入的用户名
 * @param {string} password 用户输入的密码
 * @param {string} passwordType 密码类型，'PASSWORD' 或 'ADMINPASSWORD'
 * @returns {Promise<boolean>} 验证结果
 */
async function verifyPassword(username, password, passwordType = 'PASSWORD') {
    try {
        const correctUsername = window.__ENV__?.USERNAME; // 获取正确的用户名
        const correctHash = window.__ENV__?.[passwordType]; // 获取正确的密码哈希

        // 如果用户名或密码哈希未设置，则直接返回 false
        if (!correctUsername || !correctHash) return false;

        // 检查用户名是否匹配
        if (username !== correctUsername) {
            console.warn("用户名不匹配");
            return false;
        }

        // 计算输入密码的哈希值
        const inputHash = await sha256(password);
        // 检查密码哈希是否匹配
        const isValid = inputHash === correctHash;

        if (isValid) {
            // 如果验证成功，将验证状态存储到 localStorage
            const storageKey = passwordType === 'PASSWORD'
                ? PASSWORD_CONFIG.localStorageKey
                : PASSWORD_CONFIG.adminLocalStorageKey;

            localStorage.setItem(storageKey, JSON.stringify({
                verified: true,
                timestamp: Date.now(),
                passwordHash: correctHash,
                username: correctUsername // 新增：存储验证成功的用户名
            }));
        }
        return isValid;
    } catch (error) {
        console.error(`验证${passwordType}密码时出错:`, error);
        return false;
    }
}

// 统一验证状态检查
/**
 * 检查当前用户是否已通过指定密码类型的验证
 * @param {string} passwordType 密码类型，'PASSWORD' 或 'ADMINPASSWORD'
 * @returns {boolean} 验证状态
 */
function isVerified(passwordType = 'PASSWORD') {
    try {
        // 如果未启用密码保护，则认为已验证
        if (!isPasswordProtected()) return true;

        const storageKey = passwordType === 'PASSWORD'
            ? PASSWORD_CONFIG.localStorageKey
            : PASSWORD_CONFIG.adminLocalStorageKey;

        const stored = localStorage.getItem(storageKey);
        if (!stored) return false;

        const { timestamp, passwordHash, username: storedUsername } = JSON.parse(stored);
        const currentHash = window.__ENV__?.[passwordType];
        const currentUsername = window.__ENV__?.USERNAME; // 获取当前期望的用户名

        // 验证时间戳、密码哈希和用户名是否都匹配
        return timestamp && passwordHash === currentHash && storedUsername === currentUsername &&
            Date.now() - timestamp < PASSWORD_CONFIG.verificationTTL;
    } catch (error) {
        console.error(`检查${passwordType}验证状态时出错:`, error);
        return false;
    }
}

// 更新全局导出
window.isPasswordProtected = isPasswordProtected;
window.isPasswordVerified = () => isVerified('PASSWORD');
window.isAdminVerified = () => isVerified('ADMINPASSWORD');
window.verifyPassword = verifyPassword; // verifyPassword 现在接受用户名参数

// SHA-256实现，可用Web Crypto API
async function sha256(message) {
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // HTTP 下调用原始 js‑sha256
    if (typeof window._jsSha256 === 'function') {
        return window._jsSha256(message);
    }
    throw new Error('No SHA-256 implementation available.');
}

/**
 * 显示密码验证弹窗
 */
function showPasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (passwordModal) {
        // 防止出现豆瓣区域滚动条
        document.getElementById('doubanArea').classList.add('hidden');
        document.getElementById('passwordCancelBtn').classList.add('hidden');

        passwordModal.style.display = 'flex';

        // 确保输入框获取焦点
        setTimeout(() => {
            // 新增：确保用户名输入框获取焦点
            const usernameInput = document.getElementById('usernameInput');
            if (usernameInput) {
                usernameInput.focus();
            } else {
                // 如果没有用户名输入框，则让密码输入框获取焦点
                const passwordInput = document.getElementById('passwordInput');
                if (passwordInput) {
                    passwordInput.focus();
                }
            }
        }, 100);
    }
}

/**
 * 隐藏密码验证弹窗
 */
function hidePasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (passwordModal) {
        // 隐藏密码错误提示
        hidePasswordError();

        // 清空用户名和密码输入框
        const usernameInput = document.getElementById('usernameInput');
        if (usernameInput) usernameInput.value = '';
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) passwordInput.value = '';

        passwordModal.style.display = 'none';

        // 如果启用豆瓣区域则显示豆瓣区域
        if (localStorage.getItem('doubanEnabled') === 'true') {
            document.getElementById('doubanArea').classList.remove('hidden');
            // 假设 initDouban() 是一个存在的函数
            if (typeof initDouban === 'function') {
                initDouban();
            }
        }
    }
}

/**
 * 显示密码错误信息
 */
function showPasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.classList.remove('hidden');
    }
}

/**
 * 隐藏密码错误信息
 */
function hidePasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.classList.add('hidden');
    }
}

/**
 * 处理密码提交事件（异步）
 */
async function handlePasswordSubmit() {
    const usernameInput = document.getElementById('usernameInput'); // 获取用户名输入框
    const passwordInput = document.getElementById('passwordInput'); // 获取密码输入框

    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value.trim() : '';

    // 调用 verifyPassword，传入用户名和密码
    if (await verifyPassword(username, password, 'PASSWORD')) {
        hidePasswordModal();

        // 触发密码验证成功事件
        document.dispatchEvent(new CustomEvent('passwordVerified'));
    } else {
        showPasswordError();
        // 清空密码输入框，并重新聚焦到用户名输入框
        if (passwordInput) passwordInput.value = '';
        if (usernameInput) usernameInput.focus();
    }
}

/**
 * 初始化密码验证系统（需适配异步事件）
 */
// 修改initPasswordProtection函数
function initPasswordProtection() {
    if (!isPasswordProtected()) {
        return;
    }
    
    // 检查是否有普通密码
    const hasNormalPassword = window.__ENV__?.PASSWORD &&
                              window.__ENV__.PASSWORD.length === 64 &&
                              !/^0+$/.test(window.__ENV__.PASSWORD);
    
    // 只有当设置了普通密码且未验证时才显示密码框
    // 现在也需要检查用户名是否已验证
    if (hasNormalPassword && !isPasswordVerified()) {
        showPasswordModal();
    }
    
    // 设置按钮事件监听
    const settingsBtn = document.querySelector('[onclick="toggleSettings(event)"]');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', function(e) {
            // 只有当设置了普通密码且未验证时才拦截点击
            // 现在也需要检查用户名是否已验证
            if (hasNormalPassword && !isPasswordVerified()) {
                e.preventDefault();
                e.stopPropagation();
                showPasswordModal();
                return;
            }
            
        });
    }
}

// 设置按钮密码框验证（管理员密码）
function showAdminPasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (!passwordModal) return;

    // 清空用户名和密码输入框
    const usernameInput = document.getElementById('usernameInput');
    if (usernameInput) usernameInput.value = '';
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) passwordInput.value = '';

    // 修改标题为管理员验证
    const title = passwordModal.querySelector('h2');
    if (title) title.textContent = '管理员验证';

    document.getElementById('passwordCancelBtn').classList.remove('hidden');
    passwordModal.style.display = 'flex';

    // 设置表单提交处理
    const form = document.getElementById('passwordForm');
    if (form) {
        form.onsubmit = async function (e) {
            e.preventDefault();
            const username = document.getElementById('usernameInput').value.trim(); // 获取用户名
            const password = document.getElementById('passwordInput').value.trim();
            
            // 调用 verifyPassword，传入用户名和密码，并指定为 ADMINPASSWORD 类型
            if (await verifyPassword(username, password, 'ADMINPASSWORD')) {
                passwordModal.style.display = 'none';
                // 假设 settingsPanel 是一个存在的元素
                const settingsPanel = document.getElementById('settingsPanel');
                if (settingsPanel) {
                    settingsPanel.classList.add('show');
                }
            } else {
                showPasswordError();
            }
        };
    }
}

// 在页面加载完成后初始化密码保护
document.addEventListener('DOMContentLoaded', function () {
    initPasswordProtection();
});

// SHA-256实现，可用Web Crypto API (如果原始文件中有，这里就不重复定义了，确保它只出现一次)
// 如果原始文件已经导入了 sha256，并且它是一个全局函数或模块导出，则无需再次定义。
// 这里的 sha256 函数是原始文件中提供的，为了完整性再次包含。
// 请确保您的项目中 sha256 函数的定义不会重复。
/*
async function sha256(message) {
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Narray(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // HTTP 下调用原始 js‑sha256
    if (typeof window._jsSha256 === 'function') {
        return window._jsSha256(message);
    }
    throw new Error('No SHA-256 implementation available.');
}
*/
