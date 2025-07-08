// 导入 SHA256 哈希函数，用于对密码进行哈希处理
import { sha256 } from '../js/sha256.js';

// Cloudflare Pages 的 onRequest 函数，作为中间件处理传入的请求
export async function onRequest(context) {
  // 从 context 对象中解构出 request (请求), env (环境变量), next (下一个中间件或页面处理器)
  const { request, env, next } = context;

  // 调用 next() 来获取原始的响应（例如，页面的 HTML 内容）
  const response = await next();

  // 获取响应的 Content-Type 头，如果不存在则默认为空字符串
  const contentType = response.headers.get("content-type") || "";
  
  // 检查响应是否为 HTML 类型
  if (contentType.includes("text/html")) {
    // 如果是 HTML，则读取响应的文本内容
    let html = await response.text();
    
    // --- 处理普通密码 (PASSWORD) ---
    // 从环境变量中获取 PASSWORD，如果不存在则为空字符串
    const password = env.PASSWORD || "";
    let passwordHash = "";
    // 如果 PASSWORD 存在，则计算其 SHA256 哈希值
    if (password) {
      passwordHash = await sha256(password);
    }
    // 将 HTML 中 `window.__ENV__.PASSWORD = "{{PASSWORD}}";` 占位符替换为实际的密码哈希值
    html = html.replace('window.__ENV__.PASSWORD = "{{PASSWORD}}";', 
      `window.__ENV__.PASSWORD = "${passwordHash}";`);

    // --- 处理管理员密码 (ADMINPASSWORD) ---
    // 从环境变量中获取 ADMINPASSWORD，如果不存在则为空字符串
    const adminPassword = env.ADMINPASSWORD || "";
    let adminPasswordHash = "";
    // 如果 ADMINPASSWORD 存在，则计算其 SHA256 哈希值
    if (adminPassword) {
      adminPasswordHash = await sha256(adminPassword);
    }
    // 将 HTML 中 `window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";` 占位符替换为实际的管理员密码哈希值
    html = html.replace('window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";',
      `window.__ENV__.ADMINPASSWORD = "${adminPasswordHash}";`);
    
    // --- 新增：处理用户名 (USERNAME) ---
    // 从环境变量中获取 USERNAME，如果不存在则为空字符串
    const username = env.USERNAME || "";
    let usernameProcessed = ""; // 用于存储处理后的用户名
    // 如果 USERNAME 存在，则直接使用它。
    // 注意：这里我们选择直接传递用户名，因为用户名通常不需要哈希。
    // 如果您有特殊需求需要哈希用户名，可以在这里添加 sha256(username)。
    if (username) {
        usernameProcessed = username;
    }
    // 将 HTML 中 `window.__ENV__.USERNAME = "{{USERNAME}}";` 占位符替换为实际的用户名
    // 请确保您的 HTML 文件中有这个占位符，例如：
    // <script>
    //   window.__ENV__ = window.__ENV__ || {};
    //   window.__ENV__.USERNAME = "{{USERNAME}}";
    //   window.__ENV__.PASSWORD = "{{PASSWORD}}";
    //   window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";
    // </script>
    html = html.replace('window.__ENV__.USERNAME = "{{USERNAME}}";',
      `window.__ENV__.USERNAME = "${usernameProcessed}";`);
    
    // 返回修改后的 HTML 响应，并保留原始的响应头和状态
    return new Response(html, {
      headers: response.headers,
      status: response.status,
      statusText: response.statusText,
    });
  }
  
  // 如果不是 HTML 响应，则直接返回原始响应
  return response;
}
