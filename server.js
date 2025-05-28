const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_ATLAS_URI;

if (!MONGO_URI) {
    console.error("ERRO: String de conexão do MongoDB Atlas (MONGO_ATLAS_URI) não definida no arquivo .env");
    process.exit(1);
}

mongoose.connect(MONGO_URI)
.then(() => console.log('Conectado com sucesso ao MongoDB Atlas!'))
.catch(err => {
    console.error('Erro ao conectar ao MongoDB Atlas:', err);
    process.exit(1);
});

// --- SCHEMAS ---
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "O email é obrigatório"],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/\S+@\S+\.\S+/, 'Por favor, use um email válido.']
    },
    password: {
        type: String,
        required: [true, "A senha é obrigatória"],
        minlength: [6, "A senha deve ter pelo menos 6 caracteres"]
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

const reviewSchema = new mongoose.Schema({
    movieId: {
        type: String,
        required: true,
        index: true
    },
    userId: { // Adicionado index: true para performance em buscas por userId
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
        index: true
    },
    userEmail: {
        type: String,
        required: true,
    },
    rating: {
        type: Number,
        required: [true, "A nota é obrigatória."],
        min: 0.5,
        max: 5
    },
    reviewText: {
        type: String,
        trim: true,
        maxlength: [5000, "A crítica não pode exceder 5000 caracteres."]
    },
    tags: {
        type: [String],
        default: []
    },
    isSpoiler: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

reviewSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

reviewSchema.index({ movieId: 1, userId: 1 }, { unique: true });

const Review = mongoose.model('Review', reviewSchema);

const movieItemSchema = new mongoose.Schema({
    tmdbId: { type: String, required: true },
    title: { type: String, required: true },
    posterPath: { type: String },
    addedAt: { type: Date, default: Date.now }
}, { _id: false });

const userListSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "O nome da lista é obrigatório."],
        trim: true,
        maxlength: [100, "O nome da lista não pode exceder 100 caracteres."]
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
        index: true
    },
    movies: [movieItemSchema],
    isPublic: { type: Boolean, default: false },
    description: {
        type: String,
        trim: true,
        maxlength: [500, "A descrição não pode exceder 500 caracteres."]
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

userListSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

userListSchema.index({ userId: 1, name: 1 }, { unique: true }); // Garante que um usuário não tenha listas com o mesmo nome

const UserList = mongoose.model('UserList', userListSchema);

// --- MIDDLEWARE DE PROTEÇÃO ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const JWT_SECRET = process.env.JWT_SECRET;
            if (!JWT_SECRET) {
                throw new Error('Configuração de autenticação inválida no servidor.');
            }
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = await User.findById(decoded.userId).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Usuário não encontrado para este token.' });
            }
            next();
        } catch (error) {
            if (error.name === 'JsonWebTokenError') return res.status(401).json({ message: 'Token inválido.' });
            if (error.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expirado.' });
            return res.status(401).json({ message: 'Não autorizado, falha no token.' });
        }
    }
    if (!token) {
        res.status(401).json({ message: 'Não autorizado, nenhum token fornecido.' });
    }
};

// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    if (password.length < 6) return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ message: 'Este email já está em uso.' });
        const newUser = new User({ email, password });
        await newUser.save();
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser._id });
    } catch (error) {
        if (error.code === 11000) return res.status(400).json({ message: 'Este email já está em uso (erro de duplicidade).' });
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar o usuário.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça email e senha.' });
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) return res.status(500).json({ message: "Erro de configuração do servidor (segredo JWT)." });
        const tokenPayload = { userId: user._id, email: user.email };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
        res.status(200).json({
            message: 'Login bem-sucedido!',
            token: token,
            user: { id: user._id, email: user.email }
        });
    } catch (error) {
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});

// --- ROTAS TMDB ---
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

app.get('/api/tmdb/popular', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/popular`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        res.json(response.data.results);
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes populares.' }); }
});

app.get('/api/tmdb/upcoming', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/upcoming`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        res.json(response.data.results);
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filmes em breve.' }); }
});

app.get('/api/tmdb/featured', async (req, res) => {
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/now_playing`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', page: 1 } });
        if (response.data.results && response.data.results.length > 0) res.json(response.data.results[0]);
        else res.status(404).json({ message: 'Nenhum filme em destaque encontrado.' });
    } catch (error) { res.status(error.response ? error.response.status : 500).json({ message: 'Erro ao buscar filme em destaque.' }); }
});

app.get('/api/tmdb/movie/:movieId', async (req, res) => {
    const { movieId } = req.params;
    if (!TMDB_API_KEY) return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    if (!movieId) return res.status(400).json({ message: 'O ID do filme é obrigatório.' });
    try {
        const response = await axios.get(`${TMDB_BASE_URL}/movie/${movieId}`, { params: { api_key: TMDB_API_KEY, language: 'pt-BR', append_to_response: 'credits,videos,images,release_dates,watch/providers' } });
        res.json(response.data);
    } catch (error) {
        if (error.response) res.status(error.response.status).json({ message: `Erro ao buscar detalhes do filme no TMDB: ${error.response.data.status_message || error.message}`, tmdb_status_code: error.response.data.status_code });
        else res.status(500).json({ message: `Erro interno do servidor ao buscar detalhes do filme: ${error.message}` });
    }
});


// --- ROTAS DE REVIEWS ---
app.post('/api/reviews/:movieId', protect, async (req, res) => {
    const { movieId } = req.params;
    const { rating, reviewText, tags, isSpoiler } = req.body;
    const userId = req.user._id; const userEmail = req.user.email;

    if (rating == null || typeof rating !== 'number' || rating < 0.5 || rating > 5) return res.status(400).json({ message: "A nota (rating) é obrigatória e deve ser um número entre 0.5 e 5." });
    if (reviewText && typeof reviewText !== 'string') return res.status(400).json({ message: "O texto da crítica, se fornecido, deve ser uma string."});
    if (tags && !Array.isArray(tags)) return res.status(400).json({ message: "Tags devem ser um array de strings."});
    if (isSpoiler != null && typeof isSpoiler !== 'boolean') return res.status(400).json({ message: "isSpoiler deve ser um valor booleano."});

    try {
        const reviewData = { rating, reviewText: reviewText || '', tags: tags || [], isSpoiler: isSpoiler || false, updatedAt: Date.now() };
        const existingReview = await Review.findOneAndUpdate(
            { movieId, userId },
            { ...reviewData, userEmail }, // Garante que userEmail seja definido/atualizado
            { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true } // upsert cria se não existir
        );
        res.status(existingReview.createdAt.getTime() === existingReview.updatedAt.getTime() ? 201 : 200).json({
            message: existingReview.createdAt.getTime() === existingReview.updatedAt.getTime() ? "Crítica adicionada com sucesso!" : "Crítica atualizada com sucesso!",
            review: existingReview
        });
    } catch (error) {
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') }); }
        res.status(500).json({ message: "Erro interno do servidor ao salvar a crítica." });
    }
});

app.get('/api/reviews/:movieId', async (req, res) => {
    const { movieId } = req.params;
    try {
        const reviews = await Review.find({ movieId }).sort({ createdAt: -1 });
        res.status(200).json(reviews);
    } catch (error) { res.status(500).json({ message: "Erro interno do servidor ao buscar as críticas." }); }
});

app.get('/api/movies/:movieId/stats', async (req, res) => {
    const { movieId } = req.params;
    try {
        const reviews = await Review.find({ movieId });
        if (reviews.length === 0) return res.status(200).json({ averageRating: 0, reviewCount: 0 });
        const totalRating = reviews.reduce((acc, review) => acc + review.rating, 0);
        const averageRating = totalRating / reviews.length;
        res.status(200).json({ averageRating: parseFloat(averageRating.toFixed(1)), reviewCount: reviews.length });
    } catch (error) { res.status(500).json({ message: "Erro ao calcular a nota média." }); }
});

// Endpoint para contar avaliações de um usuário específico
app.get('/api/reviews/user/:userId/count', protect, async (req, res) => {
    const { userId } = req.params;
    if (req.user._id.toString() !== userId) {
        return res.status(403).json({ message: "Não autorizado a acessar estatísticas deste usuário." });
    }
    try {
        const count = await Review.countDocuments({ userId: userId });
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar avaliações do usuário:', error);
        res.status(500).json({ message: "Erro interno do servidor ao contar as avaliações." });
    }
});


// --- ROTAS DE LISTAS DE USUÁRIOS (UserList) ---
app.post('/api/lists', protect, async (req, res) => {
    const { name, description, isPublic } = req.body; const userId = req.user._id;
    if (!name || typeof name !== 'string' || name.trim() === '') return res.status(400).json({ message: "O nome da lista é obrigatório." });
    try {
        const newList = new UserList({ name: name.trim(), userId, description: description || '', isPublic: isPublic || false, movies: [] });
        const savedList = await newList.save();
        res.status(201).json(savedList);
    } catch (error) {
        if (error.code === 11000) { return res.status(400).json({ message: `Você já possui uma lista com o nome "${name.trim()}".` });}
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') });}
        res.status(500).json({ message: "Erro ao criar a lista." });
    }
});

app.get('/api/lists', protect, async (req, res) => {
    try {
        const lists = await UserList.find({ userId: req.user._id }).sort({ updatedAt: -1 });
        res.status(200).json(lists);
    } catch (error) { res.status(500).json({ message: "Erro ao buscar as listas." }); }
});

app.get('/api/lists/:listId', protect, async (req, res) => {
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao buscar detalhes da lista.' });
    }
});

app.put('/api/lists/:listId', protect, async (req, res) => {
    const { name, description, isPublic } = req.body;
    const { listId } = req.params;
    const userId = req.user._id;

    if (!name || typeof name !== 'string' || name.trim() === '') return res.status(400).json({ message: "O nome da lista é obrigatório." });
    try {
        const list = await UserList.findOne({ _id: listId, userId });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });

        if (name.trim().toLowerCase() !== list.name.toLowerCase()) {
            const existingListWithNewName = await UserList.findOne({ userId, name: name.trim(), _id: { $ne: listId } });
            if (existingListWithNewName) {
                return res.status(400).json({ message: `Você já possui outra lista com o nome "${name.trim()}".` });
            }
        }
        
        list.name = name.trim();
        list.description = description != null ? description.trim() : ''; // Garante que description seja string
        list.isPublic = isPublic != null ? isPublic : false; // Garante que isPublic seja boolean
        list.updatedAt = Date.now();
        const updatedList = await list.save();
        res.status(200).json(updatedList);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        if (error.name === 'ValidationError') { const messages = Object.values(error.errors).map(val => val.message); return res.status(400).json({ message: messages.join(', ') });}
        res.status(500).json({ message: 'Erro ao atualizar a lista.' });
    }
});

app.delete('/api/lists/:listId', protect, async (req, res) => {
    try {
        const list = await UserList.findOneAndDelete({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada ou não pertence a este usuário.' });
        res.status(200).json({ message: 'Lista deletada com sucesso.' });
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao deletar a lista.' });
    }
});

app.post('/api/lists/:listId/movies', protect, async (req, res) => {
    const { tmdbId, title, posterPath } = req.body;
    if (!tmdbId || !title) return res.status(400).json({ message: 'ID do filme (tmdbId) e título são obrigatórios.' });
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada.' });
        if (list.movies.find(movie => movie.tmdbId === tmdbId.toString())) {
            return res.status(400).json({ message: 'Este filme já está na lista.' });
        }
        list.movies.push({ tmdbId: tmdbId.toString(), title, posterPath: posterPath || '' }); // Garante posterPath
        list.updatedAt = Date.now();
        await list.save();
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista inválido.' });
        res.status(500).json({ message: 'Erro ao adicionar filme à lista.' });
    }
});

app.delete('/api/lists/:listId/movies/:tmdbMovieId', protect, async (req, res) => {
    try {
        const list = await UserList.findOne({ _id: req.params.listId, userId: req.user._id });
        if (!list) return res.status(404).json({ message: 'Lista não encontrada.' });
        const movieIndex = list.movies.findIndex(movie => movie.tmdbId === req.params.tmdbMovieId.toString());
        if (movieIndex === -1) return res.status(404).json({ message: 'Filme não encontrado nesta lista.' });
        list.movies.splice(movieIndex, 1);
        list.updatedAt = Date.now();
        await list.save();
        res.status(200).json(list);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID da lista ou do filme inválido.' });
        res.status(500).json({ message: 'Erro ao remover filme da lista.' });
    }
});

app.get('/api/tmdb/search/movie', async (req, res) => {
    const { query } = req.query; // Pega o termo de busca dos query params (ex: /search/movie?query=Matrix)

    if (!TMDB_API_KEY) {
        return res.status(500).json({ message: 'Chave da API do TMDB não configurada no servidor.' });
    }
    if (!query || query.trim() === '') {
        return res.status(400).json({ message: 'O termo de busca (query) é obrigatório.' });
    }

    try {
        const response = await axios.get(`${TMDB_BASE_URL}/search/movie`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'pt-BR',
                query: query,
                page: 1, // Você pode adicionar paginação no futuro se desejar
                include_adult: false // Opcional: para não incluir conteúdo adulto
            }
        });
        res.json(response.data.results); // Retorna a lista de filmes encontrados
    } catch (error) {
        console.error("Erro ao buscar filmes no TMDB:", error.message);
        if (error.response) {
            res.status(error.response.status).json({ 
                message: `Erro ao buscar filmes no TMDB: ${error.response.data.status_message || error.message}`,
                tmdb_status_code: error.response.data.status_code 
            });
        } else {
            res.status(500).json({ message: `Erro interno do servidor ao buscar filmes: ${error.message}` });
        }
    }
});


// --- INICIALIZAÇÃO DO SERVIDOR ---
app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
    console.log(`Acesse em http://localhost:${PORT}.`);
});