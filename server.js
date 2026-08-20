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
const bannedUsers = new Map(); // username -> { type: 'ban'|'mute', reason, until, by }
const mutedUsers = new Map(); // username -> { until, reason, by }
const rewards = []; // 奖励记录

app.use(cors());
app.use(express.json());

// 简单鉴权中间件
function auth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token || !sessions.has(token)) {
        return res.status(401).json({ error: 'API权限未验证，请先申请访问权限' });
    }
    const username = sessions.get(token);
    
    // 检查是否被封号
    if (bannedUsers.has(username)) {
        const banInfo = bannedUsers.get(username);
        if (banInfo.type === 'permanent' || new Date(banInfo.until) > new Date()) {
            sessions.delete(token);
            return res.status(403).json({ error: `账号已被封禁，原因：${banInfo.reason}${banInfo.type === 'temporary' ? '，解封时间：' + new Date(banInfo.until).toLocaleString() : '，永久封禁'}` });
        } else {
            bannedUsers.delete(username);
        }
    }
    
    req.username = username;
    next();
}

// 检查是否被禁言
function checkMuted(username) {
    if (mutedUsers.has(username)) {
        const muteInfo = mutedUsers.get(username);
        if (new Date(muteInfo.until) > new Date()) {
            return muteInfo;
        } else {
            mutedUsers.delete(username);
        }
    }
    return null;
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
    if (bannedUsers.has(username) && bannedUsers.get(username).type === 'permanent') {
        return res.status(403).json({ error: '该用户名已被永久封禁，无法注册' });
    }
    users.push({ username, password, createdAt: new Date().toISOString() });
    res.json({ ok: true, message: '注册成功' });
});

// 用户登录
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // 检查永久封禁
    if (bannedUsers.has(username) && bannedUsers.get(username).type === 'permanent') {
        return res.status(403).json({ error: `账号已被永久封禁，原因：${bannedUsers.get(username).reason}` });
    }
    
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }
    
    // 检查临时封禁
    if (bannedUsers.has(username)) {
        const banInfo = bannedUsers.get(username);
        if (new Date(banInfo.until) > new Date()) {
            return res.status(403).json({ error: `账号已被封禁至 ${new Date(banInfo.until).toLocaleString()}，原因：${banInfo.reason}` });
        } else {
            bannedUsers.delete(username);
        }
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
    
    // 检查禁言
    const muteInfo = checkMuted(req.username);
    if (muteInfo) {
        return res.status(403).json({ error: `您已被禁言至 ${new Date(muteInfo.until).toLocaleString()}，原因：${muteInfo.reason}` });
    }
    
    const msg = {
        id: messages.length + 1,
        username: req.username,
        content: content.trim(),
        createdAt: new Date().toISOString
