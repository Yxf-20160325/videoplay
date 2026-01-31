
const { exec, execFile, spawn } = require('child_process');
const si = require('systeminformation'); // 新增：引入 systeminformation
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const uuid = require('uuid');
const os = require('os'); // 获取操作系统信息

const app = express();
const PORT = process.env.PORT || 6194;

// 定义项目内的数据存储路径
const dataDir = path.join(__dirname, 'data');
const videosFilePath = path.join(dataDir, 'videos.json');
const usersFilePath = path.join(dataDir, 'users.json');

// 确保数据目录存在，如果不存在则创建
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

/**
 * 从指定文件加载数据，如果文件不存在则使用默认值并创建文件
 * @param {string} filePath - 数据文件的路径
 * @param {any} defaultValue - 当文件不存在时使用的默认数据
 * @returns {any} - 加载或默认的数据
 */
function loadData(filePath, defaultValue) {
    try {
        if (fs.existsSync(filePath)) {
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(fileContent);
            console.log(`✅ 成功从文件加载数据: ${filePath}`);
            return data;
        } else {
            console.log(`📄 数据文件 ${filePath} 不存在，正在创建默认数据...`);
            // 确保对象在序列化前是完整的，例如将Date对象转换为ISO字符串
            const defaultValueForSave = JSON.parse(JSON.stringify(defaultValue, (key, value) => {
                if (typeof value === 'object' && value instanceof Date) {
                    return value.toISOString();
                }
                return value;
            }));
            fs.writeFileSync(filePath, JSON.stringify(defaultValueForSave, null, 2), 'utf8');
            return defaultValue;
        }
    } catch (error) {
        console.error(`❌ 加载或解析数据文件失败 (${filePath}):`, error.message);
        console.log(`🔄 将返回默认数据并尝试重新创建文件...`);
        try {
            const defaultValueForSave = JSON.parse(JSON.stringify(defaultValue, (key, value) => {
                if (typeof value === 'object' && value instanceof Date) {
                    return value.toISOString();
                }
                return value;
            }));
            fs.writeFileSync(filePath, JSON.stringify(defaultValueForSave, null, 2), 'utf8');
            console.log(`✅ 已重新创建有效的数据文件: ${filePath}`);
        } catch (writeError) {
            console.error(`❌ 甚至无法重新创建数据文件:`, writeError);
        }
        return defaultValue;
    }
}

// 用户数据模型 - 加载或初始化
const usersData = loadData(usersFilePath, {
    users: [
        {
            id: 1,
            username: 'admin',
            // 后续会替换为 bcrypt 加密后的密码
            password: 'Yxf20160325', 
            role: 'admin',
            createdAt: new Date()
        }
    ],
    sessions: {}
});


// 视频数据模型 - 加载或初始化
const videosData = loadData(videosFilePath, {
    videos: [],
    users: usersData.users // 从用户数据中同步用户列表
});

// === Express 中间件 ===
app.use(cors()); // 启用跨域资源共享
app.use(express.json()); // 解析 JSON 请求体
app.use(express.urlencoded({ extended: true })); // 解析 URL 编码的请求体

// 静态文件服务
app.use(express.static('public')); // 提供前端页面和静态资源
app.use('/videos', express.static('videos')); // 提供上传的视频文件

// 路由日志中间件
app.use((req, res, next) => {
    console.log(`${new Date().toLocaleTimeString()} - ${req.method} ${req.url}`);
    next();
});

// === Multer 文件上传配置 ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'videos');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuid.v4()}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/mov'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('仅支持视频文件 (mp4, webm, ogg, mov)'));
        }
    },
    limits: {
        fileSize: 500 * 1024 * 1024 // 500MB 限制
    }
});

/**
 * 获取服务器的局域网 IP 地址
 * @returns {string} - IP 地址或 'localhost'
 */
function getServerIp() {
    const interfaces = os.networkInterfaces();
    const ipAddresses = [];
    for (const name of Object.keys(interfaces)) {
        for (const interfaceInfo of interfaces[name]) {
            if (interfaceInfo.family === 'IPv4' && !interfaceInfo.internal) {
                ipAddresses.push(interfaceInfo.address);
            }
        }
    }
    return ipAddresses[0] || 'localhost';
}

// === 初始化：扫描已存在的视频文件 ===
if (fs.existsSync('videos')) {
    const videoFiles = fs.readdirSync('videos');
    videoFiles.forEach(file => {
        // 跳过可能的临时文件或隐藏文件
        if (file.startsWith('.')) return;
        
        const filePath = path.join('videos', file);
        const stats = fs.statSync(filePath);
        const videoExists = videosData.videos.some(v => v.filename === file);
        
        if (!videoExists) {
            console.log(`📹 发现新视频文件，正在添加到数据库: ${file}`);
            videosData.videos.push({
                id: uuid.v4(),
                title: path.parse(file).name,
                filename: file,
                url: `/videos/${file}`,
                size: stats.size,
                duration: '0:00', // 默认值，后续可集成 ffmpeg 提取
                uploadDate: stats.birthtime,
                thumbnails: []
            });
        }
    });
    // 如果有新的视频被添加，立即保存
    if(videoFiles.some(f => !videosData.videos.some(v => v.filename === f))) {
        saveVideosData();
    }
}


// === 页面路由 ===
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/watch.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'watch.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});


// === API 路由 ===

/**
 * @desc    获取所有视频的列表
 * @route   GET /api/videos
 * @access  Public
 */
app.get('/api/videos', (req, res) => {
    console.log('📺 正在获取所有视频列表，共', videosData.videos.length, '个');
    res.json({
        success: true,
        videos: videosData.videos
    });
});

/**
 * @desc    获取单个视频的详细信息
 * @route   GET /api/videos/:id
 * @access  Public
 */
app.get('/api/videos/:id', (req, res) => {
    const video = videosData.videos.find(v => v.id === req.params.id);
    if (video) {
        res.json({
            success: true,
            video
        });
    } else {
        res.status(404).json({
            success: false,
            message: '视频不存在'
        });
    }
});

/**
 * @desc    获取服务器信息（用于前端自动检测IP）
 * @route   GET /api/server/info
 * @access  Public
 */
app.get('/api/server/info', (req, res) => {
    const serverIp = getServerIp();
    res.json({
        success: true,
        serverIp,
        port: PORT
    });
});

/**
 * @desc    管理员认证中间件
 * @access  Private
 * 它会验证请求中是否带有正确的 'admin-pass' 头部，并且密码必须匹配系统中 'admin' 用户的密码。
 * 这确保了只有持有正确管理员密码的人才能访问。
 */
const isAdmin = (req, res, next) => {
    // 从请求的多个可能位置查找管理员密码
    // 从请求体、查询参数 和 请求头中获取，优先级为 body > query > header
    const providedPassword = req.body?.adminPass || req.query?.adminPass || req.headers['admin-pass'];

    if (!providedPassword) {
        console.log(`[AUTH] ❌ 权限不足: 请求来自 ${req.ip}，但缺少 'admin-pass'。`);
        return res.status(403).json({ success: false, message: '需要管理员密码验证' });
    }

    // 从用户数据中查找唯一的 'admin' 用户
    const adminUser = videosData.users.find(u => u.username === 'admin');

    // 如果系统中找不到 'admin' 用户（非常罕见）
    if (!adminUser) {
        console.error(`[AUTH] ❌ 系统严重错误: 找不到管理员用户 'admin'！`);
        return res.status(500).json({ success: false, message: '服务器配置错误，请联系管理员' });
    }

    // 验证请求提供的密码是否与数据库中的管理员密码匹配
    if (providedPassword === adminUser.password) {
        console.log(`[AUTH] ✅ 管理员认证成功，请求来自: ${req.ip}`);
        req.adminUser = adminUser; // 将用户信息附加到请求对象，供后续路由使用
        return next(); // 密码正确，允许访问
    } else {
        console.log(`[AUTH] ❌ 管理员权限验证失败，请求来自: ${req.ip}，密码错误。`);
        return res.status(403).json({ success: false, message: '管理员密码不正确' });
    }
};


// === 认证相关 API ===
app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        }
        const user = usersData.users.find(u => u.username === username && u.password === password);
        if (user) {
            const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2);
            usersData.sessions[sessionId] = {
                userId: user.id,
                username: user.username,
                role: user.role,
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24小时过期
            };
            res.json({ success: true, message: '登录成功', sessionId, user: { id: user.id, username: user.username, role: user.role } });
        } else {
            res.status(401).json({ success: false, message: '用户名或密码错误' });
        }
    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ success: false, message: '登录失败' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    try {
        const sessionId = req.body.sessionId || req.headers['session-id'] || req.query.sessionId;
        if (sessionId && usersData.sessions[sessionId]) {
            delete usersData.sessions[sessionId];
            res.json({ success: true, message: '登出成功' });
        } else {
            res.status(400).json({ success: false, message: '无效的会话ID' });
        }
    } catch (error) {
        console.error('登出错误:', error);
        res.status(500).json({ success: false, message: '登出失败' });
    }
});

const authenticateUser = (req, res, next) => {
    const sessionId = req.body?.sessionId || req.headers['session-id'] || req.query.sessionId;
    if (!sessionId) return res.status(401).json({ success: false, message: '需要登录' });
    const session = usersData.sessions[sessionId];
    if (!session) return res.status(401).json({ success: false, message: '会话已过期或无效' });
    if (new Date(session.expiresAt) < new Date()) {
        delete usersData.sessions[sessionId];
        return res.status(401).json({ success: false, message: '会话已过期，请重新登录' });
    }
    req.user = session;
    next(); // 注意：这里之前写错了，应该是 next(); 而不是 next;
};

app.get('/api/auth/user', authenticateUser, (req, res) => {
    res.json({ success: true, user: req.user });
});

// 普通用户注册功能（可选）
app.post('/api/auth/register', (req, res) => {
    try {
        const { username, password, email } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        if (username.length < 3 || password.length < 6) return res.status(400).json({ success: false, message: '用户名至少3个字符，密码至少6个字符' });
        if (usersData.users.find(u => u.username === username)) return res.status(409).json({ success: false, message: '用户名已存在' });
        const newUser = { 
            id: usersData.users.length > 0 ? Math.max(...usersData.users.map(u => u.id)) + 1 : 1, 
            username, 
            password, 
            email: email || '', 
            role: 'user', 
            createdAt: new Date() 
        };
        usersData.users.push(newUser);
        saveUsersData();
        res.json({ success: true, message: '注册成功', user: { id: newUser.id, username: newUser.username, email: newUser.email } });
    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ success: false, message: '注册失败' });
    }
});

/**
 * @desc    管理员登录接口
 * @route   POST /api/admin/login
 * @access  Public
 */
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ success: false, message: '密码不能为空' });
    }
    const adminUser = videosData.users.find(u => u.username === 'admin');
    if (!adminUser) {
        console.error('❌ 警告：系统中找不到管理员用户 "admin"!');
        return res.status(500).json({ success: false, message: '系统配置错误' });
    }
    if (password === adminUser.password) {
        console.log('✅ 管理员登录成功:', adminUser.username);
        res.json({ success: true, message: '登录成功' });
    } else {
        console.log('❌ 管理员登录失败: 密码错误');
        res.status(403).json({ success: false, message: '密码错误' });
    }
});


/**
 * @desc    获取服务器和平台的常规信息
 * @route   GET /api/admin/info
 * @access  Private (Admin)
 */
app.get('/api/admin/info', isAdmin, (req, res) => {
    const totalSize = videosData.videos.reduce((sum, video) => sum + video.size, 0);
    
    // 使用 os.totalmem() 获取总内存，这才是服务器真实的物理内存大小
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    
    // 计算已用内存，转换为 MB 并保留两位小数
    const usedMemory = (totalMemory - freeMemory) / (1024 * 1024);
    const totalMemoryMB = totalMemory / (1024 * 1024);

    res.json({
        success: true,
        info: {
            totalVideos: videosData.videos.length,
            totalSize,
            // 修正后的内存信息
            serverMemory: {
                total: totalMemoryMB.toFixed(2) + ' MB',
                used: usedMemory.toFixed(2) + ' MB',
                free: (freeMemory / (1024 * 1024)).toFixed(2) + ' MB',
                platform: os.platform()
            }
        }
    });
});

/**
 * @desc    检查是否仍在使用默认密码
 * @route   GET /api/admin/check-default-password
 * @access  Public
 */
app.get('/api/admin/check-default-password', (req, res) => {
    const isDefaultPassword = videosData.users[0].password === 'Yxf20160325';
    res.json({ success: true, isDefaultPassword });
});

/**
 * @desc    管理员修改密码接口
 * @route   PUT /api/admin/password
 * @access  Private (Admin)
 */
app.put('/api/admin/password', isAdmin, (req, res) => { // 注意：这里应该加上 isAdmin 中间件
  const { oldPassword, newPassword } = req.body;
  const adminUser = req.adminUser; // 从中间件获取已验证的 adminUser

  // 基础校验
  if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: '旧密码和新密码不能为空' });
  }
  if (oldPassword === newPassword) {
      return res.status(400).json({ success: false, message: '新密码不能和旧密码相同' });
  }
  if (oldPassword !== adminUser.password) {
      console.log(`❌ 修改密码请求失败: 管理员 ${adminUser.username} 提供的旧密码不正确。`);
      return res.status(403).json({ success: false, message: '旧密码不正确' });
  }
  if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: '新密码长度不能少于6位' });
  }

  try {
    const bcrypt = require('bcrypt');
    const saltRounds = 10;
    const newPasswordHash = bcrypt.hashSync(newPassword, saltRounds);

    // 找到数组中的管理员索引并更新密码
    const adminIndex = videosData.users.findIndex(u => u.username === 'admin');
    if (adminIndex !== -1) {
        videosData.users[adminIndex].password = newPasswordHash;
        
        // 保存回 users.json 文件
        fs.writeFileSync(path.join(__dirname, 'data', 'users.json'), JSON.stringify(usersData, null, 2), 'utf8');
        
        console.log(`✅ 管理员 ${adminUser.username} 密码修改成功。`);
        res.json({ success: true, message: '密码修改成功' });

    } else {
        console.error('❌ 修改密码时内部错误：找不到管理员用户。');
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }

  } catch (error) {
    console.error('修改密码时发生未预期的错误:', error);
    res.status(500).json({ success: false, message: '服务器内部错误' });
  }
});


// === 视频管理 API ===
/**
 * @desc    上传新视频
 * @route   POST /api/videos/upload
 * @access  Public
 */
app.post('/api/videos/upload', upload.single('video'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, message: '未选择视频文件' });
        const newVideo = { id: uuid.v4(), title: req.body.title || path.parse(req.file.originalname).name, filename: req.file.filename, url: `/videos/${req.file.filename}`, size: req.file.size, duration: '0:00', uploadDate: new Date(), thumbnails: [] };
        videosData.videos.push(newVideo);
        saveVideosData();
        res.json({ success: true, message: '视频上传成功', video: newVideo });
    } catch (error) {
        console.error('Upload error:', error);
        if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: '文件大小超过500MB限制' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
}, (error, req, res, next) => {
    res.status(500).json({ success: false, message: error.message || '文件上传失败' });
});

/**
 * @desc    更新视频信息
 * @route   PUT /api/videos/:id
 * @access  Private (Admin)
 */
app.put('/api/videos/:id', isAdmin, (req, res) => {
    try {
        const videoIndex = videosData.videos.findIndex(v => v.id === req.params.id);
        if (videoIndex === -1) return res.status(404).json({ success: false, message: '视频不存在' });
        const video = videosData.videos[videoIndex];
        if (req.body.title) video.title = req.body.title;
        if (req.body.description) video.description = req.body.description;
        saveVideosData();
        res.json({ success: true, message: '视频信息更新成功', video });
    } catch (error) {
        console.error('Update error:', error);
        res.status(500).json({ success: false, message: '更新失败: ' + error.message });
    }
});

/**
 * @desc    删除视频
 * @route   DELETE /api/videos/:id
 * @access  Private (Admin)
 */
app.delete('/api/videos/:id', isAdmin, (req, res) => {
    try {
        const videoIndex = videosData.videos.findIndex(v => v.id === req.params.id);
        if (videoIndex === -1) return res.status(404).json({ success: false, message: '视频不存在' });
        const video = videosData.videos[videoIndex];
        const filePath = path.join(__dirname, 'videos', video.filename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        videosData.videos.splice(videoIndex, 1);
        saveVideosData();
        res.json({ success: true, message: '视频删除成功' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ success: false, message: '删除失败: ' + error.message });
    }
});

/**
 * @route   GET|POST /api/admin/processes
 * @desc    获取进程列表 或 执行命令/启动新进程
 * @access  Private (Admin)
 *   - GET:  获取当前所有进程列表 (使用 systeminformation)
 *   - POST: 执行一个命令或启动一个新进程，并返回其输出和PID
 */
app.all('/api/admin/processes', isAdmin, async (req, res) => {
    // 1. 验证管理员权限 (已在 isAdmin 中间件完成)
    
    // 2. 处理 GET 请求：获取进程列表
    if (req.method === 'GET') {
        try {
            // 使用 si.processes() 获取进程列表
            // 它返回的是一个 Promise，包含了所有进程的详细信息
            const allProcs = await si.processes();
            const processes = allProcs.list;

            // 对进程列表进行格式化，使其更易读
            const formattedProcesses = processes.map(p => ({
                pid: p.pid,
                name: p.name,
                // p.cpu 是当前进程的 CPU 使用率百分比
                cpu: parseFloat(p.cpu) || 0,
                // p.mem 是当前进程的内存使用量（字节），我们将其转换为 MB
                memory: (p.mem / (1024 * 1024)),
                cmd: p.command || p.name, // 显示完整的命令行或进程名
                user: p.user // 进程所属用户
            }));

            res.json({
                success: true,
                // si.processes() 还包含 all 和 list，这里我们只返回 list
                processes: formattedProcesses 
            });
        } catch (error) {
            console.error('[PROC] 使用 systeminformation 获取进程列表失败:', error);
            res.status(500).json({ success: false, message: '获取进程列表失败: ' + error.message });
        }
        return; // GET 请求处理完毕
    }

    // 3. 处理 POST 请求：执行命令或启动进程
    // 这部分逻辑与之前完全相同，无需修改
    if (req.method === 'POST') {
        const { command, args = [], isDetached = false } = req.body;
        if (!command) {
            return res.status(400).json({ success: false, message: '请提供要执行的命令' });
        }
        console.log(`[CMD] 正在执行命令: ${command} ${args.join(' ')}`);

        if (isDetached) {
            // 启动一个独立的后台进程
            const child = spawn(command, args, { detached: true, stdio: 'ignore' });
            child.unref(); // 让父进程可以退出，不影响子进程
            console.log(`[CMD] 已在后台启动进程，PID: ${child.pid}`);
            return res.json({ success: true, message: '程序已在后台启动', pid: child.pid });
        } else {
            // 在 Shell 中执行命令并捕获输出
            // Windows: cmd /c "command args"
            // Linux/macOS: "command args"
            let execCommand;
            if (process.platform === 'win32') {
                // 在 Windows 上，参数需要用引号括起来，以防空格
                const argsStr = args.map(arg => `"${arg}"`).join(' ');
                execCommand = `cmd.exe /c "${command}" ${argsStr}`;
            } else {
                execCommand = `${command} ${args.join(' ')}`;
            }
            
            exec(execCommand, { timeout: 15000 }, (error, stdout, stderr) => { // 15秒超时
                let output = stdout;
                let message = '命令执行成功';
                let success = true;

                if (error) {
                    success = false;
                    message = `命令执行出错: ${error.message}`;
                    output = stderr || error.message;
                    console.error(`[CMD] 执行失败: ${execCommand}`, error);
                } else if (stderr) {
                    // 即使成功，也可能有 stderr
                    output = `--- 标准输出 ---\n${stdout}\n\n--- 标准错误 ---\n${stderr}`;
                    console.warn(`[CMD] 命令有错误输出: ${execCommand}`, stderr);
                } else {
                    console.log(`[CMD] 执行成功: ${execCommand}`, stdout);
                }
                
                res.json({
                    success: success,
                    command: execCommand,
                    message: message,
                    output: output
                });
            });
        }
    }
});

/**
 * @route   POST /api/admin/processes/:pid/terminate
 * @desc    终止一个指定PID的进程
 * @access  Private (Admin)
 */
app.post('/api/admin/processes/:pid/terminate', isAdmin, async (req, res) => { // 加上 isAdmin
    const pid = parseInt(req.params.pid);
    if (isNaN(pid)) return res.status(400).json({ success: false, message: '无效的进程ID' });
    console.log(`[PROC] 正在尝试结束进程: ${pid}`);
    try {
        if (process.platform === 'win32') {
            await exec(`taskkill /PID ${pid} /F`);
        } else {
            await exec(`kill -9 ${pid}`);
        }
        console.log(`[PROC] 成功结束进程: ${pid}`);
        res.json({ success: true, message: `进程 ${pid} 已成功结束` });
    } catch (err) {
        console.error(`[PROC] 结束进程失败: ${pid}`, err);
        res.status(500).json({ success: false, message: '结束进程失败: ' + err.message });
    }
});


/**
 * @route   GET /api/server/status
 * @desc    获取服务器运行状态
 * @access  Private (Admin)
 */
app.get('/api/server/status', isAdmin, async (req, res) => {
    const uptime = process.uptime();
    
    // 使用 systeminformation 获取更准确的内存信息
    try {
        const memInfo = await si.mem();
        const osInfo = await si.osInfo(); // 获取操作系统信息
        
        // 同时获取进程列表，让状态页面更完整
        const allProcs = await si.processes();
        const topProcs = allProcs.list.slice(0, 10); // 只取前10个最占资源的进程

        res.json({
            success: true,
            status: 'running',
            pid: process.pid,
            nodeVersion: process.version,
            platform: process.platform,
            // 使用 si 提供的内存信息
            memory: {
                total: (memInfo.total / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
                free: (memInfo.free / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
                used: (memInfo.used / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
                usagePercent: memInfo.usedmem
            },
            uptime: uptime,
            prettyUptime: formatUptime(uptime),
            osPlatform: osInfo.platform, // e.g., 'Linux', 'Windows', 'Darwin'
            hostname: osInfo.hostname,
            // 返回前10个进程用于前端展示
            topProcesses: topProcs.map(p => ({
                pid: p.pid,
                name: p.name,
                cpu: parseFloat(p.cpu) || 0,
                memory: (p.mem / (1024 * 1024)), // 注意：这里不使用 .toFixed()，让前端处理
                cmd: p.command || p.name
            }))
        });
    } catch (error) {
        console.error('[STATUS] 获取系统信息失败:', error);
        // 如果 si 失败，回退到基础的 os 模块信息
        res.json({
            success: true,
            status: 'running',
            pid: process.pid,
            nodeVersion: process.version,
            platform: process.platform,
            memoryUsage: process.memoryUsage(),
            uptime: uptime,
            prettyUptime: formatUptime(uptime),
            error: '无法获取详细系统信息，正在使用备用数据。'
        });
    }
});


app.post('/api/server/shutdown', isAdmin, (req, res) => { // 加上 isAdmin
    console.log('🛑 Shutdown request received from admin. Server is shutting down...');
    res.json({ success: true, message: '服务器关闭命令已接收，正在安全关闭中...' });
    setTimeout(() => process.exit(0), 2000);
});

// === 辅助函数 ===
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    let uptimeString = '';
    if (days > 0) uptimeString += `${days}天 `;
    if (hours > 0 || days > 0) uptimeString += `${hours}小时 `;
    if (minutes > 0 || hours > 0 || days > 0) uptimeString += `${minutes}分钟 `;
    uptimeString += `${secs}秒`;
    return uptimeString.trim();
}

function saveVideosData() {
    try {
        const dataToSave = JSON.parse(JSON.stringify(videosData));
        if (dataToSave.videos && Array.isArray(dataToSave.videos)) {
            dataToSave.videos.forEach(video => {
                if (video.createdAt && video.createdAt instanceof Date) {
                    video.createdAt = video.createdAt.toISOString();
                }
            });
        }
        fs.writeFileSync(videosFilePath, JSON.stringify(dataToSave, null, 2), 'utf8');
        console.log(`✅ 视频数据已成功保存到: ${videosFilePath}`);
    } catch (error) {
        console.error('❌ 保存视频数据失败:', error);
    }
}

function saveUsersData() {
    try {
        fs.writeFileSync(usersFilePath, JSON.stringify(usersData, null, 2), 'utf8');
        console.log('✅ 用户数据已自动保存');
    } catch (error) {
        console.error('❌ 保存用户数据失败:', error);
    }
}

// === 错误处理与启动 ===
// 404处理
app.use((req, res) => {
    if (req.originalUrl.startsWith('/api/')) {
        res.status(404).json({ success: false, message: 'API端点不存在' });
    } else {
        res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
    }
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: '服务器内部错误' });
});

// 启动服务器
const serverInstance = app.listen(PORT, () => {
    const serverIp = getServerIp();
    console.log(`==========================================`);
    console.log(`🚀 视频播放平台服务器已启动:`);
    console.log(`   本地访问: http://localhost:${PORT}`);
    console.log(`   局域网访问: http://${serverIp}:${PORT}`);
    console.log(`🔑 管理员密码: Yxf20160325 (首次登录请修改)`);
    console.log(`🏠 首页: http://localhost:${PORT}`);
    console.log(`⚙️  管理后台: http://localhost:${PORT}/admin.html`);
    console.log(`🎬 视频播放: http://localhost:${PORT}/watch.html?video=视频ID`);
    console.log(`==========================================`);
    process.env.SERVER_START_TIME = new Date().toISOString();
});

// 优雅关闭：保存数据并退出
const gracefulShutdown = () => {
    console.log('\n接收到终止信号，正在关闭服务器...');
    saveVideosData();
    saveUsersData();
    serverInstance.close(() => {
        console.log('✅ 服务器已关闭，所有数据已保存。');
        process.exit(0);
    });
};

process.on('SIGINT', gracefulShutdown); // 监听 Ctrl+C
process.on('SIGTERM', gracefulShutdown); // 监听 kill 命令
