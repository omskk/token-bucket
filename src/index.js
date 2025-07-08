/**
 * Token Bucket - Cloudflare Worker
 * 使用 KV 存储 token 并提供 API 和页面展示
 */

// HTML 页面模板
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Token 管理</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      color: #333;
    }
    h1 {
      color: #2c3e50;
      border-bottom: 1px solid #eee;
      padding-bottom: 10px;
    }
    .container {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .card {
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .form-group {
      margin-bottom: 15px;
    }
    label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
    }
    textarea {
      width: 100%;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      height: 120px;
      font-family: monospace;
      box-sizing: border-box;
    }
    button {
      background-color: #3498db;
      color: white;
      border: none;
      padding: 10px 15px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background-color: #2980b9;
    }
    .token-count {
      margin-bottom: 10px;
      font-weight: bold;
    }
    .status {
      margin-top: 10px;
      padding: 10px;
      border-radius: 4px;
    }
    .success {
      background-color: #d4edda;
      color: #155724;
    }
    .error {
      background-color: #f8d7da;
      color: #721c24;
    }
    
    /* 表格样式 */
    .token-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      overflow-x: auto;
      display: block;
    }
    .token-table th, .token-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #eee;
      word-break: break-all;
    }
    .token-table th {
      background-color: #f8f9fa;
      font-weight: 600;
    }
    .token-table tr:hover {
      background-color: #f5f5f5;
    }
    
    /* 弹窗样式 */
    .modal {
      display: none;
      position: fixed;
      z-index: 1000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0,0,0,0.4);
      overflow-y: auto;
    }
    .modal-content {
      background-color: #fff;
      margin: 5% auto;
      padding: 20px;
      border-radius: 8px;
      width: 90%;
      max-width: 600px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.1);
      position: relative;
    }
    .close {
      color: #aaa;
      position: absolute;
      right: 20px;
      top: 10px;
      font-size: 28px;
      font-weight: bold;
      cursor: pointer;
    }
    .close:hover {
      color: #333;
    }
    
    /* 按钮组样式 */
    .btn-group {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    
    /* 表格为空时的样式 */
    .empty-table {
      text-align: center;
      padding: 30px;
      color: #666;
      font-style: italic;
    }
    
    /* 状态标签样式 */
    .status-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
    }
    .status-true {
      background-color: #ffeeba;
      color: #856404;
    }
    .status-false {
      background-color: #d1e7dd;
      color: #0f5132;
    }
    
    /* 删除按钮样式 */
    .delete-btn {
      background-color: #dc3545;
      color: white;
      border: none;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    .delete-btn:hover {
      background-color: #c82333;
    }
    
    /* 授权按钮样式 */
    .auth-btn {
      background-color: #28a745;
      color: white;
      border: none;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      margin-right: 10px;
    }
    .auth-btn:hover {
      background-color: #218838;
    }
    
    /* 授权URL结果样式 */
    .auth-result {
      margin-top: 15px;
      padding: 15px;
      background-color: #f8f9fa;
      border-radius: 4px;
      border: 1px solid #ddd;
      display: none;
    }
    .auth-result pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      font-family: monospace;
      font-size: 14px;
    }
    .copy-btn {
      background-color: #6c757d;
      color: white;
      border: none;
      padding: 3px 8px;
      border-radius: 3px;
      cursor: pointer;
      font-size: 12px;
      margin-top: 10px;
    }
    .copy-btn:hover {
      background-color: #5a6268;
    }
    
    /* 管理员登录模态框 */
    .admin-section {
      margin-top: 20px;
      text-align: right;
    }
    .admin-link {
      color: #6c757d;
      text-decoration: none;
      font-size: 14px;
      cursor: pointer;
    }
    .admin-link:hover {
      text-decoration: underline;
    }
    .login-form {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }
    .form-control {
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 16px;
    }
    
    /* 响应式调整 */
    @media (max-width: 768px) {
      .modal-content {
        width: 95%;
        margin: 10% auto;
      }
      .token-table th, .token-table td {
        padding: 8px;
        font-size: 14px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Token 管理系统</h1>
    
    <div class="card">
      <div class="btn-group">
        <button id="openModalBtn">添加新 Token</button>
        <button id="refreshBtn">刷新列表</button>
        <span id="adminStatus" style="margin-left: auto; color: #28a745; display: none;">
          已登录为管理员
        </span>
      </div>
      
      <div id="tokenCount" class="token-count">加载中...</div>
      
      <div style="overflow-x: auto;">
        <table class="token-table">
          <thead>
            <tr>
              <th>Token</th>
              <th>租户 URL</th>
              <th>使用次数</th>
              <th>冷却状态</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="tokenTableBody">
            <tr>
              <td colspan="5" class="empty-table">加载中...</td>
            </tr>
          </tbody>
        </table>
      </div>
      
      <div class="admin-section">
        <a href="#" class="admin-link" id="adminLoginLink">管理员登录</a>
      </div>
    </div>
  </div>
  
  <!-- 添加 Token 的弹窗 -->
  <div id="addTokenModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>添加新 Token</h2>
      
      <div class="btn-group">
        <button id="getAuthUrlBtn" class="auth-btn">获取授权地址</button>
      </div>
      
      <div id="authUrlResult" class="auth-result">
        <h3>授权信息</h3>
        <p><strong>授权 URL:</strong></p>
        <pre id="authUrlText"></pre>
        <button id="copyAuthUrlBtn" class="copy-btn">复制 URL</button>
        
        <p><strong>Code Verifier:</strong></p>
        <pre id="codeVerifierText"></pre>
        <button id="copyVerifierBtn" class="copy-btn">复制 Verifier</button>
        
        <p><strong>State:</strong></p>
        <pre id="stateText"></pre>
        <button id="copyStateBtn" class="copy-btn">复制 State</button>
      </div>
      
      <div class="form-group">
        <label for="tokenInput">Token 数据 (JSON 格式):</label>
        <textarea id="tokenInput" placeholder='{"code":"_2a9cdea3b11f264543f57d5285abc827","state":"FUbGpOpOobI","tenant_url":"https://d6.api.augmentcode.com/"}'></textarea>
      </div>
      <button id="addTokenBtn">添加 Token</button>
      <div id="addStatus" class="status" style="display: none;"></div>
    </div>
  </div>
  
  <!-- 管理员登录弹窗 -->
  <div id="adminLoginModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>管理员登录</h2>
      <div class="login-form">
        <input type="password" id="adminPassword" class="form-control" placeholder="请输入管理员密钥">
        <button id="adminLoginBtn">登录</button>
      </div>
      <div id="loginStatus" class="status" style="display: none;"></div>
    </div>
  </div>

  <script>
    // 存储管理员状态
    let isAdmin = false;
    let adminToken = '';
    
    // 检查本地存储中是否有管理员 token
    function checkAdminStatus() {
      const savedToken = localStorage.getItem('admin_token');
      if (savedToken) {
        adminToken = savedToken;
        isAdmin = true;
        document.getElementById('adminStatus').style.display = 'inline';
      }
    }
    
    // 获取所有 token
    async function getTokens() {
      try {
        const headers = {};
        if (isAdmin && adminToken) {
          headers['X-Auth-Token'] = adminToken;
        }
        
        const response = await fetch('/api/tokens', { headers });
        const data = await response.json();
        
        if (data.status === 'success') {
          const tableBody = document.getElementById('tokenTableBody');
          tableBody.innerHTML = '';
          
          document.getElementById('tokenCount').textContent = \`共有 \${data.total} 个 Token\`;
          
          if (data.tokens.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" class="empty-table">暂无 Token 数据</td></tr>';
            return;
          }
          
          data.tokens.forEach((token, index) => {
            const row = document.createElement('tr');
            
            // 格式化创建时间
            const createdDate = new Date(token.created_at);
            const formattedDate = createdDate.toLocaleString('zh-CN');
            
            // 构建表格行
            row.innerHTML = \`
              <td>\${token.token}</td>
              <td>\${token.tenant_url}</td>
              <td>\${token.usage_count}</td>
              <td><span class="status-badge status-\${token.in_cool}">\${token.in_cool ? '冷却中' : '可用'}</span></td>
              <td>\${formattedDate}</td>
              \${isAdmin ? \`<td><button class="delete-btn" data-token="\${token.token}">删除</button></td>\` : '<td>-</td>'}
            \`;
            
            tableBody.appendChild(row);
          });
          
          // 为所有删除按钮添加事件监听器
          if (isAdmin) {
            document.querySelectorAll('.delete-btn').forEach(btn => {
              btn.addEventListener('click', function() {
                const tokenToDelete = this.getAttribute('data-token');
                if (confirm(\`确定要删除 Token "\${tokenToDelete.substring(0, 10)}..." 吗？\`)) {
                  deleteToken(tokenToDelete);
                }
              });
            });
          }
        } else {
          throw new Error(data.message || '获取 Token 失败');
        }
      } catch (error) {
        console.error('获取 Token 出错:', error);
        document.getElementById('tokenTableBody').innerHTML = 
          \`<tr><td colspan="6" class="empty-table">获取 Token 失败: \${error.message}</td></tr>\`;
      }
    }
    
    // 删除指定的 token
    async function deleteToken(tokenToDelete) {
      try {
        const headers = {};
        if (isAdmin && adminToken) {
          headers['X-Auth-Token'] = adminToken;
        }
        
        const response = await fetch(\`/api/token/\${tokenToDelete}\`, {
          method: 'DELETE',
          headers: headers
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
          alert('Token 删除成功！');
          // 刷新 token 列表
          getTokens();
        } else {
          throw new Error(data.message || '删除 Token 失败');
        }
      } catch (error) {
        console.error('删除 Token 出错:', error);
        alert(\`删除失败: \${error.message}\`);
      }
    }
    
    // 获取授权地址
    async function getAuthUrl() {
      try {
        // 生成 code_verifier (使用 crypto.randomUUID 和 SHA-256)
        const randomBytes = crypto.randomUUID();
        const codeVerifierBytes = await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(randomBytes)
        );
        const codeVerifier = base64UrlEncode(codeVerifierBytes);
        
        // 生成 code_challenge
        const codeChallengeBytes = await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(codeVerifier)
        );
        const codeChallenge = base64UrlEncode(codeChallengeBytes);
        
        // 生成 state 参数
        const state = crypto.randomUUID();
        
        // 构造授权 URL 参数
        const params = new URLSearchParams({
          response_type: 'code',
          code_challenge: codeChallenge,
          client_id: 'v',
          state: state,
          prompt: 'login'
        });
        
        // 构建完整的授权 URL
        const authUrl = \`https://auth.augmentcode.com/authorize?\${params.toString()}\`;
        
        // 显示结果
        document.getElementById('authUrlText').textContent = authUrl;
        document.getElementById('codeVerifierText').textContent = codeVerifier;
        document.getElementById('stateText').textContent = state;
        document.getElementById('authUrlResult').style.display = 'block';
        
        // 更新输入框中的 state
        const tokenInput = document.getElementById('tokenInput');
        try {
          const tokenData = JSON.parse(tokenInput.value);
          tokenData.state = state;
          tokenInput.value = JSON.stringify(tokenData, null, 2);
        } catch (e) {
          // 如果输入框中不是有效的 JSON，则不更新
          console.error('无法解析输入框中的 JSON:', e);
        }
        
        return { authUrl, codeVerifier, state };
      } catch (error) {
        console.error('获取授权地址出错:', error);
        alert(\`获取授权地址失败: \${error.message}\`);
      }
    }
    
    // Base64 URL 编码函数
    function base64UrlEncode(buffer) {
      return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\\+/g, '-')
        .replace(/\\//g, '_')
        .replace(/=/g, '');
    }
    
    // 复制文本到剪贴板
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('已复制到剪贴板');
      }).catch(err => {
        console.error('复制失败:', err);
        // 备用方法
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('已复制到剪贴板');
      });
    }
    
    // 添加新 token
    async function addToken() {
      const tokenInput = document.getElementById('tokenInput');
      const addStatus = document.getElementById('addStatus');
      
      try {
        // 验证输入是否为有效的 JSON
        const tokenData = JSON.parse(tokenInput.value);
        
        const headers = {
          'Content-Type': 'application/json'
        };
        
        if (isAdmin && adminToken) {
          headers['X-Auth-Token'] = adminToken;
        }
        
        const response = await fetch('/api/add_token', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(tokenData),
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
          addStatus.textContent = '添加成功！';
          addStatus.className = 'status success';
          addStatus.style.display = 'block';
          
          // 清空输入框
          tokenInput.value = '';
          
          // 刷新 token 列表
          getTokens();
          
          // 3秒后关闭弹窗
          setTimeout(() => {
            document.getElementById('addTokenModal').style.display = 'none';
            addStatus.style.display = 'none';
          }, 3000);
        } else {
          throw new Error(data.message || '添加 Token 失败');
        }
      } catch (error) {
        console.error('添加 Token 出错:', error);
        addStatus.textContent = \`添加失败: \${error.message}\`;
        addStatus.className = 'status error';
        addStatus.style.display = 'block';
      }
    }
    
    // 管理员登录
    function adminLogin() {
      const password = document.getElementById('adminPassword').value;
      const loginStatus = document.getElementById('loginStatus');
      
      if (!password) {
        loginStatus.textContent = '请输入密钥';
        loginStatus.className = 'status error';
        loginStatus.style.display = 'block';
        return;
      }
      
      // 保存到本地存储
      localStorage.setItem('admin_token', password);
      adminToken = password;
      isAdmin = true;
      
      // 更新界面
      document.getElementById('adminStatus').style.display = 'inline';
      document.getElementById('adminLoginModal').style.display = 'none';
      document.getElementById('adminPassword').value = '';
      
      // 刷新 token 列表
      getTokens();
      
      loginStatus.textContent = '登录成功！';
      loginStatus.className = 'status success';
      loginStatus.style.display = 'block';
    }
    
    // 弹窗控制
    function setupModals() {
      // 添加 Token 弹窗
      const addTokenModal = document.getElementById('addTokenModal');
      const openAddModalBtn = document.getElementById('openModalBtn');
      const closeAddModalBtn = addTokenModal.querySelector('.close');
      
      openAddModalBtn.onclick = function() {
        addTokenModal.style.display = 'block';
      }
      
      closeAddModalBtn.onclick = function() {
        addTokenModal.style.display = 'none';
        document.getElementById('addStatus').style.display = 'none';
      }
      
      // 管理员登录弹窗
      const adminModal = document.getElementById('adminLoginModal');
      const openAdminModalBtn = document.getElementById('adminLoginLink');
      const closeAdminModalBtn = adminModal.querySelector('.close');
      
      openAdminModalBtn.onclick = function(e) {
        e.preventDefault();
        adminModal.style.display = 'block';
      }
      
      closeAdminModalBtn.onclick = function() {
        adminModal.style.display = 'none';
        document.getElementById('loginStatus').style.display = 'none';
      }
      
      // 点击弹窗外部关闭
      window.onclick = function(event) {
        if (event.target == addTokenModal) {
          addTokenModal.style.display = 'none';
          document.getElementById('addStatus').style.display = 'none';
        }
        if (event.target == adminModal) {
          adminModal.style.display = 'none';
          document.getElementById('loginStatus').style.display = 'none';
        }
      }
    }
    
    // 页面加载完成后执行
    document.addEventListener('DOMContentLoaded', () => {
      // 检查管理员状态
      checkAdminStatus();
      
      // 初始化获取 token 列表
      getTokens();
      
      // 设置弹窗
      setupModals();
      
      // 添加 token 按钮事件
      document.getElementById('addTokenBtn').addEventListener('click', addToken);
      
      // 获取授权地址按钮事件
      document.getElementById('getAuthUrlBtn').addEventListener('click', getAuthUrl);
      
      // 复制按钮事件
      document.getElementById('copyAuthUrlBtn').addEventListener('click', function() {
        copyToClipboard(document.getElementById('authUrlText').textContent);
      });
      
      document.getElementById('copyVerifierBtn').addEventListener('click', function() {
        copyToClipboard(document.getElementById('codeVerifierText').textContent);
      });
      
      document.getElementById('copyStateBtn').addEventListener('click', function() {
        copyToClipboard(document.getElementById('stateText').textContent);
      });
      
      // 管理员登录按钮事件
      document.getElementById('adminLoginBtn').addEventListener('click', adminLogin);
      
      // 管理员密码输入框回车事件
      document.getElementById('adminPassword').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          adminLogin();
        }
      });
      
      // 刷新按钮事件
      document.getElementById('refreshBtn').addEventListener('click', getTokens);
      
      // 设置默认的 token 数据
      document.getElementById('tokenInput').value = 
        '{"code":"_2a9cdea3b11f264543f57d5285abc827","state":"FUbGpOpOobI","tenant_url":"https://d6.api.augmentcode.com/"}';
    });
  </script>
</body>
</html>`;

// 处理请求的主函数
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 检查是否是 API 请求
  if (path.startsWith('/api/')) {
    // 获取 AUTH_KEY 环境变量
    const authKey = env.AUTH_KEY || '';
    
    // 获取请求头中的 X-Auth-Token
    const authToken = request.headers.get('X-Auth-Token') || '';
    
    // 如果环境变量中设置了 AUTH_KEY，则进行鉴权验证
    if (authKey && authToken !== authKey) {
      return new Response(JSON.stringify({
        status: 'error',
        message: '鉴权失败，无效的 Token'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // API 路由
    if (path === '/api/tokens' && request.method === 'GET') {
      return handleGetTokens(env);
    } else if (path === '/api/add_token' && request.method === 'POST') {
      return handleAddToken(request, env);
    } else if (path.startsWith('/api/token/') && request.method === 'DELETE') {
      // 提取 token 值
      const tokenToDelete = path.substring('/api/token/'.length);
      return handleDeleteToken(tokenToDelete, env);
    }
  }
  
  // 默认返回 HTML 页面
  return new Response(HTML_CONTENT, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
    },
  });
}

// 获取所有 token
async function handleGetTokens(env) {
  try {
    // 获取所有 token 的键
    const keys = await env.KV.list();
    
    // 获取每个 token 的值
    const tokens = [];
    for (const key of keys.keys) {
      const value = await env.KV.get(key.name, { type: 'json' });
      if (value) {
        tokens.push(value);
      }
    }
    
    return new Response(JSON.stringify({
      status: 'success',
      tokens: tokens,
      total: tokens.length
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: error.message || '获取 token 失败'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 添加新 token
async function handleAddToken(request, env) {
  try {
    // 解析请求体
    const inputData = await request.json();
    
    // 构建标准化的 token 数据结构
    const tokenData = {
      token: inputData.code || inputData.token || "",
      tenant_url: inputData.tenant_url || "",
      usage_count: inputData.usage_count || 0,
      in_cool: inputData.in_cool || false,
      created_at: inputData.created_at || new Date().toISOString()
    };
    
    // 生成唯一 ID 作为 KV 存储的键
    const id = crypto.randomUUID();
    
    // 存储 token 数据
    await env.KV.put(id, JSON.stringify(tokenData));
    
    return new Response(JSON.stringify({
      status: 'success',
      message: 'Token 添加成功'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: error.message || '添加 token 失败'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 删除指定的 token
async function handleDeleteToken(tokenToDelete, env) {
  try {
    // 获取所有 token 的键
    const keys = await env.KV.list();
    let deleted = false;
    let deletedKey = null;
    
    // 遍历所有 token，查找匹配的 token 值
    for (const key of keys.keys) {
      const value = await env.KV.get(key.name, { type: 'json' });
      if (value && value.token === tokenToDelete) {
        // 找到匹配的 token，删除它
        await env.KV.delete(key.name);
        deleted = true;
        deletedKey = key.name;
        break;
      }
    }
    
    if (deleted) {
      return new Response(JSON.stringify({
        status: 'success',
        message: 'Token 删除成功',
        key: deletedKey
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({
        status: 'error',
        message: '未找到指定的 Token'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: error.message || '删除 Token 失败'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 导出处理函数
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
}; 