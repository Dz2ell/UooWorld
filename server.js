require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const TwitchStrategy = require('passport-twitch-new').Strategy;
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const multer = require('multer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Multer config for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public/uploads/crafts'));
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `craft-${Date.now()}${ext}`);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images allowed'));
    }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport serialize/deserialize
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = db.findUserById(id);
    done(null, user);
});

// OAuth callback handler helper
function handleOAuthLogin(provider, idField, profile, done) {
    let user = db.findUserByOAuthId(provider, profile.id);
    if (!user) {
        const email = profile.emails?.[0]?.value || profile.email;
        user = email ? db.findUserByEmail(email) : null;
        if (user) {
            // Link provider to existing account
            db.updateUserProfile(user.id, { [idField]: profile.id });
        } else {
            // Create new user
            user = db.createUserFromOAuth({
                [idField]: profile.id,
                username: profile.displayName || profile.username || email?.split('@')[0] || `user_${Date.now()}`,
                email: email,
                avatar_url: profile.photos?.[0]?.value || profile.avatar
            });
        }
    }
    done(null, user);
}

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback'
    }, (accessToken, refreshToken, profile, done) => {
        handleOAuthLogin('google', 'google_id', profile, done);
    }));
    console.log('✅ Google OAuth enabled');
} else {
    console.log('⚠️  Google OAuth disabled (no credentials in .env)');
}

// Discord OAuth Strategy
if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
    passport.use(new DiscordStrategy({
        clientID: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        callbackURL: '/auth/discord/callback',
        scope: ['identify', 'email']
    }, (accessToken, refreshToken, profile, done) => {
        profile.photos = [{ value: `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` }];
        handleOAuthLogin('discord', 'discord_id', profile, done);
    }));
    console.log('✅ Discord OAuth enabled');
} else {
    console.log('⚠️  Discord OAuth disabled (no credentials in .env)');
}

// Twitch OAuth Strategy
if (process.env.TWITCH_CLIENT_ID && process.env.TWITCH_CLIENT_SECRET) {
    passport.use(new TwitchStrategy({
        clientID: process.env.TWITCH_CLIENT_ID,
        clientSecret: process.env.TWITCH_CLIENT_SECRET,
        callbackURL: '/auth/twitch/callback',
        scope: 'user:read:email'
    }, (accessToken, refreshToken, profile, done) => {
        handleOAuthLogin('twitch', 'twitch_id', profile, done);
    }));
    console.log('✅ Twitch OAuth enabled');
} else {
    console.log('⚠️  Twitch OAuth disabled (no credentials in .env)');
}


// ============================================
// MIDDLEWARE
// ============================================

// Auth middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Необходима авторизация' });
    }
    next();
};

// Role-level middleware
const requireLevel = (minLevel) => (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Необходима авторизация' });
    }
    const user = db.findUserById(req.session.userId);
    if (!user || (user.level || 1) < minLevel) {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
    req.user = user;
    next();
};

// ============================================
// AUTH ROUTES
// ============================================


// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Имя пользователя должно быть минимум 3 символа' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
        }

        // Check if user exists
        if (db.userExists(username, email)) {
            return res.status(400).json({ error: 'Пользователь с таким именем или email уже существует' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create user
        const newUser = db.createUser(username, email, passwordHash);

        // Set session
        req.session.userId = newUser.id;
        req.session.username = username;

        res.json({
            success: true,
            user: { id: newUser.id, username, email }
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Ошибка регистрации' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, totp_code } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        // Find user
        const user = db.findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        // Check if 2FA is enabled
        if (user.totp_enabled && user.totp_secret) {
            if (!totp_code) {
                // Return that 2FA is required
                return res.status(200).json({ requires_2fa: true });
            }

            // Verify 2FA code
            const valid2FA = speakeasy.totp.verify({
                secret: user.totp_secret,
                encoding: 'base32',
                token: totp_code,
                window: 1
            });

            if (!valid2FA) {
                return res.status(401).json({ error: 'Неверный код 2FA' });
            }
        }

        // Set session
        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Ошибка входа' });
    }
});


// Logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка выхода' });
        }
        res.json({ success: true });
    });
});

// Get current user
app.get('/api/auth/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Не авторизован' });
    }

    const user = db.findUserById(req.session.userId);

    if (!user) {
        return res.status(404).json({ error: 'Пользователь не найден' });
    }

    // Don't send password hash
    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser });
});

// ============================================
// GOOGLE OAUTH ROUTES
// ============================================

// Start Google OAuth
app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID) {
        return res.redirect('/?error=google_not_configured');
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// Google OAuth Callback
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/?error=google' }),
    (req, res) => {
        req.session.userId = req.user.id;
        req.session.username = req.user.username;
        res.redirect('/');
    }
);

// ============================================
// DISCORD OAUTH ROUTES  
// ============================================

// Start Discord OAuth
app.get('/auth/discord', (req, res, next) => {
    if (!process.env.DISCORD_CLIENT_ID) {
        return res.redirect('/?error=discord_not_configured');
    }
    passport.authenticate('discord')(req, res, next);
});

// Discord OAuth Callback
app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/?error=discord' }),
    (req, res) => {
        req.session.userId = req.user.id;
        req.session.username = req.user.username;
        res.redirect('/');
    }
);

// ============================================
// TWITCH OAUTH ROUTES
// ============================================

// Start Twitch OAuth
app.get('/auth/twitch', (req, res, next) => {
    if (!process.env.TWITCH_CLIENT_ID) {
        return res.redirect('/?error=twitch_not_configured');
    }
    passport.authenticate('twitch')(req, res, next);
});

// Twitch OAuth Callback
app.get('/auth/twitch/callback',
    passport.authenticate('twitch', { failureRedirect: '/?error=twitch' }),
    (req, res) => {
        req.session.userId = req.user.id;
        req.session.username = req.user.username;
        res.redirect('/');
    }
);

// ============================================
// IMAGE UPLOAD
// ============================================

// Upload craft image
app.post('/api/upload/craft', requireLevel(3), upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
    }
    const imageUrl = `/uploads/crafts/${req.file.filename}`;
    res.json({ success: true, url: imageUrl });
});


// ============================================
// PROFILE ROUTES
// ============================================

// Update profile
app.put('/api/profile', requireAuth, (req, res) => {
    try {
        const { minecraft_username, bio, discord_username } = req.body;

        const user = db.updateUserProfile(req.session.userId, {
            minecraft_username: minecraft_username || null,
            bio: bio || null,
            discord_username: discord_username || null
        });

        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const { password_hash, ...safeUser } = user;
        res.json({ success: true, user: safeUser });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Ошибка обновления профиля' });
    }
});

// Publish profile to Discord
app.post('/api/profile/publish', requireAuth, async (req, res) => {
    try {
        const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

        if (!webhookUrl) {
            return res.status(400).json({ error: 'Discord Webhook не настроен. Добавьте DISCORD_WEBHOOK_URL в .env файл.' });
        }

        const user = db.findUserById(req.session.userId);

        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Create Discord embed
        const embed = {
            title: `🎮 Профиль игрока: ${user.username}`,
            color: 0x22c55e, // Green color
            fields: [
                {
                    name: '⛏️ Minecraft ник',
                    value: user.minecraft_username || 'Не указан',
                    inline: true
                },
                {
                    name: '💬 Discord',
                    value: user.discord_username || 'Не указан',
                    inline: true
                },
                {
                    name: '📝 О себе',
                    value: user.bio || 'Пока ничего не написал...',
                    inline: false
                }
            ],
            footer: {
                text: 'UooWorld — Приватный Ванильный Сервер'
            },
            timestamp: new Date().toISOString()
        };

        // Send to Discord
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [embed]
            })
        });

        if (!response.ok) {
            throw new Error('Discord webhook failed');
        }

        res.json({ success: true, message: 'Профиль опубликован в Discord!' });

    } catch (error) {
        console.error('Discord publish error:', error);
        res.status(500).json({ error: 'Ошибка публикации в Discord' });
    }
});

// ============================================
// ACCOUNT SETTINGS API
// ============================================

// Change email
app.put('/api/settings/email', requireAuth, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = db.findUserById(req.session.userId);

        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

        // Verify password if user has one
        if (user.password_hash) {
            if (!password) return res.status(400).json({ error: 'Введите пароль' });
            const valid = await bcrypt.compare(password, user.password_hash);
            if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
        }

        // Check if email taken
        const existing = db.findUserByEmail(email);
        if (existing && existing.id !== user.id) {
            return res.status(400).json({ error: 'Email уже используется' });
        }

        db.updateUserProfile(user.id, { email });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Change password
app.put('/api/settings/password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = db.findUserById(req.session.userId);

        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

        // Verify current password if exists
        if (user.password_hash) {
            if (!currentPassword) return res.status(400).json({ error: 'Введите текущий пароль' });
            const valid = await bcrypt.compare(currentPassword, user.password_hash);
            if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
        }

        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Пароль минимум 6 символов' });
        }

        const hash = await bcrypt.hash(newPassword, 10);
        db.updateUserProfile(user.id, { password_hash: hash });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Setup 2FA - generate secret
app.post('/api/settings/2fa/setup', requireAuth, async (req, res) => {
    try {
        const user = db.findUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

        const secret = speakeasy.generateSecret({
            name: `UooWorld (${user.username})`,
            length: 20
        });

        // Store temp secret (not enabled yet)
        db.updateUserProfile(user.id, { totp_secret: secret.base32 });

        // Generate QR code
        const qrUrl = await QRCode.toDataURL(secret.otpauth_url);

        res.json({ success: true, qrCode: qrUrl, secret: secret.base32 });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Verify and enable 2FA
app.post('/api/settings/2fa/verify', requireAuth, (req, res) => {
    try {
        const { code } = req.body;
        const user = db.findUserById(req.session.userId);

        if (!user || !user.totp_secret) {
            return res.status(400).json({ error: 'Сначала получите QR код' });
        }

        const valid = speakeasy.totp.verify({
            secret: user.totp_secret,
            encoding: 'base32',
            token: code
        });

        if (!valid) {
            return res.status(400).json({ error: 'Неверный код' });
        }

        db.updateUserProfile(user.id, { totp_enabled: true });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Disable 2FA
app.post('/api/settings/2fa/disable', requireAuth, async (req, res) => {
    try {
        const { password, code } = req.body;
        const user = db.findUserById(req.session.userId);

        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

        // Verify password
        if (user.password_hash) {
            if (!password) return res.status(400).json({ error: 'Введите пароль' });
            const valid = await bcrypt.compare(password, user.password_hash);
            if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
        }

        // Verify 2FA code
        if (user.totp_enabled && user.totp_secret) {
            const valid = speakeasy.totp.verify({
                secret: user.totp_secret,
                encoding: 'base32',
                token: code
            });
            if (!valid) return res.status(400).json({ error: 'Неверный 2FA код' });
        }

        db.updateUserProfile(user.id, { totp_secret: null, totp_enabled: false });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Unlink OAuth provider
app.post('/api/settings/unlink/:provider', requireAuth, async (req, res) => {
    try {
        const { provider } = req.params;
        const { password } = req.body;
        const user = db.findUserById(req.session.userId);

        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

        const validProviders = ['google', 'discord', 'twitch'];
        if (!validProviders.includes(provider)) {
            return res.status(400).json({ error: 'Неизвестный провайдер' });
        }

        // Must have password or another OAuth to unlink
        const linkedProviders = validProviders.filter(p => user[`${p}_id`]);
        if (!user.password_hash && linkedProviders.length <= 1) {
            return res.status(400).json({ error: 'Нужен пароль или другой способ входа' });
        }

        // Verify password if exists
        if (user.password_hash && password) {
            const valid = await bcrypt.compare(password, user.password_hash);
            if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
        }

        db.updateUserProfile(user.id, { [`${provider}_id`]: null });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// ROLES API
// ============================================

// Get role commands
app.get('/api/roles/:level/commands', (req, res) => {
    const level = parseInt(req.params.level);
    const roleInfo = db.getRoleInfo(level);
    res.json({
        level,
        role: roleInfo.name,
        commands: roleInfo.commands || []
    });
});

// Get all roles (for admin panel)
app.get('/api/roles', (req, res) => {
    res.json({ roles: db.getAllRoles() });
});

// ============================================
// WIKI API
// ============================================

// Get all crafts
app.get('/api/wiki', (req, res) => {
    const crafts = db.getAllCrafts();
    res.json({ crafts });
});

// Get craft by ID
app.get('/api/wiki/:id', (req, res) => {
    const craft = db.getCraftById(parseInt(req.params.id));
    if (!craft) {
        return res.status(404).json({ error: 'Крафт не найден' });
    }
    res.json({ craft });
});

// Create craft (mod+)
app.post('/api/wiki', requireLevel(3), (req, res) => {
    try {
        const { title, description, recipe, image_url } = req.body;
        if (!title || !description) {
            return res.status(400).json({ error: 'Название и описание обязательны' });
        }
        const craft = db.createCraft({
            title,
            description,
            recipe: recipe || null,
            image_url: image_url || null,
            created_by: req.user.id
        });
        res.json({ success: true, craft });
    } catch (error) {
        console.error('Create craft error:', error);
        res.status(500).json({ error: 'Ошибка создания' });
    }
});

// Update craft (mod+)
app.put('/api/wiki/:id', requireLevel(3), (req, res) => {
    try {
        const { title, description, recipe, image_url } = req.body;
        const craft = db.updateCraft(parseInt(req.params.id), {
            title, description, recipe, image_url
        });
        if (!craft) {
            return res.status(404).json({ error: 'Крафт не найден' });
        }
        res.json({ success: true, craft });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка обновления' });
    }
});

// Delete craft (admin only)
app.delete('/api/wiki/:id', requireLevel(4), (req, res) => {
    db.deleteCraft(parseInt(req.params.id));
    res.json({ success: true });
});

// ============================================
// SUPPORT API
// ============================================

// Create ticket
app.post('/api/support', requireAuth, (req, res) => {
    try {
        const { subject, message } = req.body;
        if (!subject || !message) {
            return res.status(400).json({ error: 'Тема и сообщение обязательны' });
        }
        const ticket = db.createTicket(req.session.userId, subject, message);
        res.json({ success: true, ticket });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка создания тикета' });
    }
});

// Get my tickets
app.get('/api/support/my', requireAuth, (req, res) => {
    const tickets = db.getTicketsByUser(req.session.userId);
    res.json({ tickets });
});

// Get all tickets (helper+)
app.get('/api/support', requireLevel(2), (req, res) => {
    const tickets = db.getAllTickets();
    // Add user info
    const ticketsWithUser = tickets.map(t => {
        const user = db.findUserById(t.user_id);
        return { ...t, username: user?.username || 'Unknown' };
    });
    res.json({ tickets: ticketsWithUser });
});

// Get ticket details with replies
app.get('/api/support/:id', requireAuth, (req, res) => {
    const ticket = db.getTicketById(parseInt(req.params.id));
    if (!ticket) {
        return res.status(404).json({ error: 'Тикет не найден' });
    }
    // Check permission
    const user = db.findUserById(req.session.userId);
    if (ticket.user_id !== req.session.userId && (user?.level || 1) < 2) {
        return res.status(403).json({ error: 'Нет доступа' });
    }
    const replies = db.getTicketReplies(ticket.id);
    // Add usernames to replies
    const repliesWithUser = replies.map(r => {
        const u = db.findUserById(r.user_id);
        return { ...r, username: u?.username || 'Unknown', level: u?.level || 1 };
    });
    res.json({ ticket, replies: repliesWithUser });
});

// Reply to ticket (helper+)
app.post('/api/support/:id/reply', requireLevel(2), (req, res) => {
    try {
        const { message, status } = req.body;
        const ticketId = parseInt(req.params.id);

        if (message) {
            db.addTicketReply(ticketId, req.user.id, message);
        }
        if (status) {
            db.updateTicketStatus(ticketId, status);
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка ответа' });
    }
});

// ============================================
// FORUM API
// ============================================

// Get all posts
app.get('/api/forum', (req, res) => {
    const posts = db.getAllPosts();
    // Add author info
    const postsWithAuthor = posts.map(p => {
        const author = db.findUserById(p.author_id);
        return {
            ...p,
            author_name: author?.username || 'Unknown',
            author_level: author?.level || 1
        };
    });
    res.json({ posts: postsWithAuthor });
});

// Get post by ID
app.get('/api/forum/:id', (req, res) => {
    const post = db.getPostById(parseInt(req.params.id));
    if (!post) {
        return res.status(404).json({ error: 'Тема не найдена' });
    }
    const author = db.findUserById(post.author_id);
    res.json({
        post: {
            ...post,
            author_name: author?.username || 'Unknown',
            author_level: author?.level || 1
        }
    });
});

// Create post (admin only)
app.post('/api/forum', requireLevel(4), (req, res) => {
    try {
        const { title, content, tags } = req.body;
        if (!title || !content) {
            return res.status(400).json({ error: 'Название и содержание обязательны' });
        }
        const post = db.createPost(req.user.id, title, content, tags || []);
        res.json({ success: true, post });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка создания темы' });
    }
});

// Vote on post
app.post('/api/forum/:id/vote', requireAuth, (req, res) => {
    try {
        const { vote } = req.body; // 'yes' or 'no'
        if (!['yes', 'no'].includes(vote)) {
            return res.status(400).json({ error: 'Неверный голос' });
        }
        const post = db.voteOnPost(parseInt(req.params.id), req.session.userId, vote);
        if (!post) {
            return res.status(404).json({ error: 'Тема не найдена' });
        }
        res.json({ success: true, post });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка голосования' });
    }
});

// Close post (admin only)
app.put('/api/forum/:id/close', requireLevel(4), (req, res) => {
    const post = db.closePost(parseInt(req.params.id));
    if (!post) {
        return res.status(404).json({ error: 'Тема не найдена' });
    }
    res.json({ success: true, post });
});

// ============================================
// TAGS API
// ============================================

// Get all tags
app.get('/api/tags', (req, res) => {
    res.json({ tags: db.getAllTags() });
});

// Add tag (admin only)
app.post('/api/tags', requireLevel(4), (req, res) => {
    const { tag } = req.body;
    if (!tag) {
        return res.status(400).json({ error: 'Тег обязателен' });
    }
    const tags = db.addTag(tag);
    res.json({ success: true, tags });
});

// Remove tag (admin only)
app.delete('/api/tags/:tag', requireLevel(4), (req, res) => {
    const tags = db.removeTag(req.params.tag);
    res.json({ success: true, tags });
});

// ============================================
// FALLBACK ROUTE
// ============================================

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🎮 UooWorld Server запущен!                         ║
║                                                       ║
║   📍 http://localhost:${PORT}                           ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
    `);
});
