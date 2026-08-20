// server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// 内存存储
const users = [];
const messages = [];
const bugs = [];
const reports = [];
const sessions = new Map(); // token -> username

app.use(cors());
app.use(express.json());

// 简单鉴权中间件
function auth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token || !sessions.has(token)) {
        return res.status(401).json({ error: 'API权限未验证，请先申请访问权限' });
    }
    req.username = sessions.get(token);
    next();
}

// 生成token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// 测试接口
app.get('/api/ping', (req, res) => {
    res.json({ ok: true, message: 'pong', time: new Date().toISOString() });
});

// 用户注册
app.post('/api/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) {
        return res.status(400).json({ error: '请填写完整信息' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ error: '两次密码不一致' });
    }
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: '用户名已存在' });
    }
    users.push({ username, password, createdAt: new Date().toISOString() });
    res.json({ ok: true, message: '注册成功' });
});

// 用户登录
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }
    const token = generateToken();
    sessions.set(token, username);
    res.json({ ok: true, token, username });
});

// 退出登录
app.post('/api/logout', auth, (req, res) => {
    const token = req.headers.authorization.replace('Bearer ', '');
    sessions.delete(token);
    res.json({ ok: true, message: '已退出' });
});

// 发送聊天消息
app.post('/api/messages', auth, (req, res) => {
    const { content } = req.body;
    if (!content || !content.trim()) {
        return res.status(400).json({ error: '消息不能为空' });
    }
    const msg = {
        id: messages.length + 1,
        username: req.username,
        content: content.trim(),
        createdAt: new Date().toISOString()
    };
    messages.push(msg);
    res.json({ ok: true, message: msg });
});

// 获取聊天记录
app.get('/api/messages', auth, (req, res) => {
    res.json({ ok: true, messages });
});

// 提交bug反馈
app.post('/api/bugs', auth, (req, res) => {
    const { title, description } = req.body;
    if (!title || !description) {
        return res.status(400).json({ error: '请填写完整反馈信息' });
    }
    const bug = {
        id: bugs.length + 1,
        username: req.username,
        title,
        description,
        status: 'pending',
        createdAt: new Date().toISOString()
    };
    bugs.push(bug);
    res.json({ ok: true, message: '反馈已提交', bug });
});

// 提交举报
app.post('/api/reports', auth, (req, res) => {
    const { targetUsername, reason, messageId } = req.body;
    if (!targetUsername || !reason) {
        return res.status(400).json({ error: '请填写被举报人和举报原因' });
    }
    const report = {
        id: reports.length + 1,
        reporter: req.username,
        targetUsername,
        reason,
        messageId: messageId || null,
        status: 'pending',
        createdAt: new Date().toISOString()
    };
    reports.push(report);
    res.json({ ok: true, message: '举报已提交', report });
});

// ========== 管理后台接口（无密码，但需要权限令牌） ==========
// 管理后台权限令牌从环境变量读取
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'dev-admin-secret-change-me';

function adminAuth(req, res, next) {
    const adminToken = req.headers['x-admin-token'];
    if (!adminToken || adminToken !== ADMIN_SECRET) {
        return res.status(403).json({ error: '管理权限验证失败，请提供有效的x-admin-token' });
    }
    next();
}

// 获取所有用户
app.get('/api/admin/users', adminAuth, (req, res) => {
    res.json({ ok: true, users: users.map(u => ({ username: u.username, createdAt: u.createdAt })) });
});

// 获取所有聊天记录
app.get('/api/admin/messages', adminAuth, (req, res) => {
    res.json({ ok: true, messages });
});

// 获取bug反馈列表
app.get('/api/admin/bugs', adminAuth, (req, res) => {
    res.json({ ok: true, bugs });
});

// 更新bug状态
app.put('/api/admin/bugs/:id', adminAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const bug = bugs.find(b => b.id === id);
    if (!bug) {
        return res.status(404).json({ error: '反馈不存在' });
    }
    bug.status = req.body.status || bug.status;
    bug.adminNote = req.body.adminNote || bug.adminNote;
    res.json({ ok: true, bug });
});

// 获取举报列表
app.get('/api/admin/reports', adminAuth, (req, res) => {
    res.json({ ok: true, reports });
});

// 处理举报
app.put('/api/admin/reports/:id', adminAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const report = reports.find(r => r.id === id);
    if (!report) {
        return res.status(404).json({ error: '举报不存在' });
    }
    report.status = req.body.status || report.status;
    report.adminNote = req.body.adminNote || report.adminNote;
    res.json({ ok: true, report });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
