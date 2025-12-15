const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data');
const USERS_FILE = path.join(DB_PATH, 'users.json');
const WIKI_FILE = path.join(DB_PATH, 'wiki.json');
const SUPPORT_FILE = path.join(DB_PATH, 'support.json');
const FORUM_FILE = path.join(DB_PATH, 'forum.json');
const TAGS_FILE = path.join(DB_PATH, 'tags.json');

// Role definitions
const ROLES = {
    1: { name: 'Игрок', nameEn: 'Player', color: '#94a3b8', commands: [] },
    2: {
        name: 'Хелпер',
        nameEn: 'Helper',
        color: '#22d3ee',
        commands: [
            { cmd: '/warn <player> <reason>', desc: 'Выдать предупреждение игроку' },
            { cmd: '/mute <player> <time>', desc: 'Замутить игрока' }
        ]
    },
    3: {
        name: 'Модератор',
        nameEn: 'Moderator',
        color: '#a78bfa',
        commands: [
            { cmd: '/warn <player> <reason>', desc: 'Выдать предупреждение игроку' },
            { cmd: '/mute <player> <time>', desc: 'Замутить игрока' },
            { cmd: '/unmute <player>', desc: 'Размутить игрока' },
            { cmd: '/kick <player> <reason>', desc: 'Кикнуть игрока' },
            { cmd: '/tempban <player> <time>', desc: 'Временный бан' }
        ]
    },
    4: {
        name: 'Администратор',
        nameEn: 'Administrator',
        color: '#f43f5e',
        commands: [
            { cmd: '/warn <player> <reason>', desc: 'Выдать предупреждение игроку' },
            { cmd: '/mute <player> <time>', desc: 'Замутить игрока' },
            { cmd: '/unmute <player>', desc: 'Размутить игрока' },
            { cmd: '/kick <player> <reason>', desc: 'Кикнуть игрока' },
            { cmd: '/tempban <player> <time>', desc: 'Временный бан' },
            { cmd: '/ban <player> <reason>', desc: 'Перманентный бан' },
            { cmd: '/unban <player>', desc: 'Разбанить игрока' },
            { cmd: '/whitelist add <player>', desc: 'Добавить в whitelist' },
            { cmd: '/whitelist remove <player>', desc: 'Убрать из whitelist' },
            { cmd: '/op <player>', desc: 'Выдать оператора' },
            { cmd: '/deop <player>', desc: 'Забрать оператора' }
        ]
    }
};

// Ensure data directory exists
if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(DB_PATH, { recursive: true });
}

// Initialize files
function initFile(filePath, defaultData) {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
    }
}

initFile(USERS_FILE, { users: [], nextId: 1 });
initFile(WIKI_FILE, { crafts: [], nextId: 1 });
initFile(SUPPORT_FILE, { tickets: [], replies: [], nextId: 1 });
initFile(FORUM_FILE, { posts: [], nextId: 1 });
initFile(TAGS_FILE, { tags: ['спавн', 'постройка', 'ивент', 'правила', 'идея'], nextId: 6 });

// ============================================
// USERS
// ============================================

function getUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')).users;
}

function saveUsersData(data) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

function findUserByEmail(email) {
    return getUsers().find(u => u.email === email);
}

function findUserByUsername(username) {
    return getUsers().find(u => u.username === username);
}

function findUserById(id) {
    return getUsers().find(u => u.id === id);
}

function userExists(username, email) {
    return getUsers().some(u => u.username === username || u.email === email);
}

function createUser(username, email, passwordHash) {
    const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const newUser = {
        id: data.nextId,
        username,
        email,
        password_hash: passwordHash,
        minecraft_username: null,
        bio: null,
        discord_username: null,
        avatar_url: null,
        level: 1,
        role_title: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };
    data.users.push(newUser);
    data.nextId++;
    saveUsersData(data);
    return newUser;
}

function updateUserProfile(id, updates) {
    const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const idx = data.users.findIndex(u => u.id === id);
    if (idx === -1) return null;
    data.users[idx] = { ...data.users[idx], ...updates, updated_at: new Date().toISOString() };
    saveUsersData(data);
    return data.users[idx];
}

// OAuth functions for all providers
function findUserByOAuthId(provider, id) {
    const field = `${provider}_id`;
    return getUsers().find(u => u[field] === id);
}

// Legacy function for backward compatibility
function findUserByGoogleId(googleId) {
    return findUserByOAuthId('google', googleId);
}

function createUserFromOAuth(data) {
    const fileData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const newUser = {
        id: fileData.nextId,
        username: data.username,
        email: data.email || null,
        password_hash: null, // No password for OAuth users
        google_id: data.google_id || null,
        discord_id: data.discord_id || null,
        twitch_id: data.twitch_id || null,
        minecraft_username: null,
        bio: null,
        discord_username: null,
        avatar_url: data.avatar_url || null,
        level: 1,
        role_title: null,
        totp_secret: null,
        totp_enabled: false,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };
    fileData.users.push(newUser);
    fileData.nextId++;
    saveUsersData(fileData);
    return newUser;
}

// Legacy function for backward compatibility
function createUserFromGoogle(data) {
    return createUserFromOAuth(data);
}

function getRoleInfo(level) {
    return ROLES[level] || ROLES[1];
}

function getAllRoles() {
    return ROLES;
}


// ============================================
// WIKI (Crafts)
// ============================================

function getWikiData() {
    return JSON.parse(fs.readFileSync(WIKI_FILE, 'utf8'));
}

function saveWikiData(data) {
    fs.writeFileSync(WIKI_FILE, JSON.stringify(data, null, 2));
}

function getAllCrafts() {
    return getWikiData().crafts;
}

function getCraftById(id) {
    return getAllCrafts().find(c => c.id === id);
}

function createCraft(craft) {
    const data = getWikiData();
    const newCraft = {
        id: data.nextId,
        ...craft,
        created_at: new Date().toISOString()
    };
    data.crafts.push(newCraft);
    data.nextId++;
    saveWikiData(data);
    return newCraft;
}

function updateCraft(id, updates) {
    const data = getWikiData();
    const idx = data.crafts.findIndex(c => c.id === id);
    if (idx === -1) return null;
    data.crafts[idx] = { ...data.crafts[idx], ...updates, updated_at: new Date().toISOString() };
    saveWikiData(data);
    return data.crafts[idx];
}

function deleteCraft(id) {
    const data = getWikiData();
    data.crafts = data.crafts.filter(c => c.id !== id);
    saveWikiData(data);
}

// ============================================
// SUPPORT TICKETS
// ============================================

function getSupportData() {
    return JSON.parse(fs.readFileSync(SUPPORT_FILE, 'utf8'));
}

function saveSupportData(data) {
    fs.writeFileSync(SUPPORT_FILE, JSON.stringify(data, null, 2));
}

function getAllTickets() {
    return getSupportData().tickets;
}

function getTicketsByUser(userId) {
    return getAllTickets().filter(t => t.user_id === userId);
}

function getTicketById(id) {
    return getAllTickets().find(t => t.id === id);
}

function createTicket(userId, subject, message) {
    const data = getSupportData();
    const ticket = {
        id: data.nextId,
        user_id: userId,
        subject,
        message,
        status: 'open',
        created_at: new Date().toISOString()
    };
    data.tickets.push(ticket);
    data.nextId++;
    saveSupportData(data);
    return ticket;
}

function updateTicketStatus(id, status) {
    const data = getSupportData();
    const idx = data.tickets.findIndex(t => t.id === id);
    if (idx === -1) return null;
    data.tickets[idx].status = status;
    saveSupportData(data);
    return data.tickets[idx];
}

function getTicketReplies(ticketId) {
    return getSupportData().replies.filter(r => r.ticket_id === ticketId);
}

function addTicketReply(ticketId, userId, message) {
    const data = getSupportData();
    const reply = {
        id: Date.now(),
        ticket_id: ticketId,
        user_id: userId,
        message,
        created_at: new Date().toISOString()
    };
    data.replies.push(reply);
    saveSupportData(data);
    return reply;
}

// ============================================
// FORUM
// ============================================

function getForumData() {
    return JSON.parse(fs.readFileSync(FORUM_FILE, 'utf8'));
}

function saveForumData(data) {
    fs.writeFileSync(FORUM_FILE, JSON.stringify(data, null, 2));
}

function getAllPosts() {
    return getForumData().posts;
}

function getPostById(id) {
    return getAllPosts().find(p => p.id === id);
}

function createPost(authorId, title, content, tags) {
    const data = getForumData();
    const post = {
        id: data.nextId,
        author_id: authorId,
        title,
        content,
        tags: tags || [],
        votes_yes: 0,
        votes_no: 0,
        voters: [],
        status: 'open',
        created_at: new Date().toISOString()
    };
    data.posts.push(post);
    data.nextId++;
    saveForumData(data);
    return post;
}

function voteOnPost(postId, userId, vote) {
    const data = getForumData();
    const idx = data.posts.findIndex(p => p.id === postId);
    if (idx === -1) return null;

    const post = data.posts[idx];

    // Check if already voted
    const existingVote = post.voters.find(v => v.userId === userId);
    if (existingVote) {
        // Change vote
        if (existingVote.vote !== vote) {
            if (existingVote.vote === 'yes') post.votes_yes--;
            else post.votes_no--;
            if (vote === 'yes') post.votes_yes++;
            else post.votes_no++;
            existingVote.vote = vote;
        }
    } else {
        // New vote
        post.voters.push({ userId, vote });
        if (vote === 'yes') post.votes_yes++;
        else post.votes_no++;
    }

    saveForumData(data);
    return post;
}

function closePost(postId) {
    const data = getForumData();
    const idx = data.posts.findIndex(p => p.id === postId);
    if (idx === -1) return null;
    data.posts[idx].status = 'closed';
    saveForumData(data);
    return data.posts[idx];
}

// ============================================
// TAGS
// ============================================

function getTagsData() {
    return JSON.parse(fs.readFileSync(TAGS_FILE, 'utf8'));
}

function saveTagsData(data) {
    fs.writeFileSync(TAGS_FILE, JSON.stringify(data, null, 2));
}

function getAllTags() {
    return getTagsData().tags;
}

function addTag(tag) {
    const data = getTagsData();
    if (!data.tags.includes(tag)) {
        data.tags.push(tag);
        saveTagsData(data);
    }
    return data.tags;
}

function removeTag(tag) {
    const data = getTagsData();
    data.tags = data.tags.filter(t => t !== tag);
    saveTagsData(data);
    return data.tags;
}

console.log('✅ Database initialized (JSON storage with wiki, forum, support)');

module.exports = {
    // Users
    findUserByEmail,
    findUserByUsername,
    findUserById,
    findUserByGoogleId,
    findUserByOAuthId,
    userExists,
    createUser,
    createUserFromGoogle,
    createUserFromOAuth,
    updateUserProfile,
    getRoleInfo,
    getAllRoles,
    ROLES,

    // Wiki
    getAllCrafts,
    getCraftById,
    createCraft,
    updateCraft,
    deleteCraft,

    // Support
    getAllTickets,
    getTicketsByUser,
    getTicketById,
    createTicket,
    updateTicketStatus,
    getTicketReplies,
    addTicketReply,

    // Forum
    getAllPosts,
    getPostById,
    createPost,
    voteOnPost,
    closePost,

    // Tags
    getAllTags,
    addTag,
    removeTag
};
