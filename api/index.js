// ============================================
// BACKEND COMPLETO - ZERO DEPENDÊNCIAS
// ============================================

// CONFIGURAÇÃO (será preenchida pelas variáveis de ambiente)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@clinica.com';

// Função principal da Vercel Serverless
module.exports = async (req, res) => {
    // Configurar CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    
    // Lidar com preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    // Extrair path e método
    const { method, url } = req;
    const path = url.split('?')[0];
    
    try {
        // Roteamento baseado no path
        switch (true) {
            case path === '/' && method === 'GET':
                return res.json({ api: 'Clinica Ficha Digital', status: 'online', version: '1.0' });
            
            case path === '/login' && method === 'POST':
                return await handleLogin(req, res);
            
            case path === '/registrar' && method === 'POST':
                return await handleRegister(req, res);
            
            case path === '/me' && method === 'GET':
                return await handleGetMe(req, res);
            
            case path.includes('/orientacao/') && path.includes('/lida') && method === 'PUT':
                return await handleMarcarLida(req, res, path);
            
            case path === '/admin/pacientes' && method === 'GET':
                return await handleAdminPacientes(req, res);
            
            case path.includes('/admin/paciente/') && method === 'GET':
                return await handleAdminPaciente(req, res, path);
            
            case path === '/admin/enviar-documento' && method === 'POST':
                return await handleEnviarDocumento(req, res);
            
            case path === '/admin/enviar-orientacao' && method === 'POST':
                return await handleEnviarOrientacao(req, res);
            
            case path === '/admin/adicionar-foto' && method === 'POST':
                return await handleAdicionarFoto(req, res);
            
            default:
                return res.status(404).json({ error: 'Rota não encontrada' });
        }
    } catch (error) {
        console.error('Erro:', error);
        return res.status(500).json({ error: 'Erro interno do servidor' });
    }
};

// ========== FUNÇÕES AUXILIARES ==========

async function fetchSupabase(endpoint, options = {}) {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/${endpoint}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            ...options.headers
        }
    });
    
    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Supabase error: ${error}`);
    }
    
    return response.json();
}

async function authSupabase(endpoint, options = {}) {
    const response = await fetch(`${SUPABASE_URL}/auth/v1/${endpoint}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'apikey': SUPABASE_KEY,
            ...options.headers
        }
    });
    
    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Auth error: ${error}`);
    }
    
    return response.json();
}

async function verifyToken(token) {
    try {
        const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'apikey': SUPABASE_KEY
            }
        });
        
        if (!response.ok) return null;
        
        const data = await response.json();
        return data.user;
    } catch {
        return null;
    }
}

async function obterPacienteId(userId) {
    const [paciente] = await fetchSupabase(`pacientes?user_id=eq.${userId}&select=id`);
    return paciente ? paciente.id : null;
}

// ========== HANDLERS ==========

async function handleLogin(req, res) {
    const { email, password } = await parseBody(req);
    
    try {
        // Autenticar no Supabase
        const authData = await authSupabase('token?grant_type=password', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        
        if (!authData.user) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        // Buscar paciente
        const [paciente] = await fetchSupabase(`pacientes?user_id=eq.${authData.user.id}&select=*`);
        
        return res.json({
            success: true,
            user: authData.user,
            paciente: paciente || null,
            token: authData.access_token
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
}

async function handleRegister(req, res) {
    const { email, password, nome, telefone, data_nascimento } = await parseBody(req);
    
    try {
        // Registrar usuário
        const authData = await authSupabase('signup', {
            method: 'POST',
            body: JSON.stringify({ email, password, data: { nome } })
        });
        
        if (!authData.user) {
            return res.status(400).json({ error: 'Erro ao criar usuário' });
        }
        
        // Criar paciente
        await fetchSupabase('pacientes', {
            method: 'POST',
            body: JSON.stringify([{
                user_id: authData.user.id,
                nome,
                email,
                telefone,
                data_nascimento
            }])
        });
        
        return res.json({
            success: true,
            message: 'Registro realizado!',
            user: authData.user
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
}

async function handleGetMe(req, res) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    
    const pacienteId = await obterPacienteId(user.id);
    if (!pacienteId) return res.status(404).json({ error: 'Paciente não encontrado' });
    
    // Buscar todos os dados em paralelo
    const [pacientes, consultas, documentos, fotos, orientacoes] = await Promise.all([
        fetchSupabase(`pacientes?user_id=eq.${user.id}&select=*`),
        fetchSupabase(`consultas?paciente_id=eq.${pacienteId}&select=*&order=data.desc`),
        fetchSupabase(`documentos?paciente_id=eq.${pacienteId}&select=*&order=created_at.desc`),
        fetchSupabase(`fotos?paciente_id=eq.${pacienteId}&select=*&order=data.desc`),
        fetchSupabase(`orientacoes?paciente_id=eq.${pacienteId}&lida=eq.false&select=*&order=created_at.desc`)
    ]);
    
    return res.json({
        paciente: pacientes[0] || null,
        consultas: consultas || [],
        documentos: documentos || [],
        fotos: fotos || [],
        orientacoes: orientacoes || []
    });
}

async function handleMarcarLida(req, res, path) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    
    const id = path.split('/')[2]; // Extrair ID da URL
    
    await fetchSupabase(`orientacoes?id=eq.${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ lida: true })
    });
    
    return res.json({ success: true });
}

async function handleAdminPacientes(req, res) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user || user.email !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const pacientes = await fetchSupabase('pacientes?select=*&order=nome.asc');
    return res.json(pacientes);
}

async function handleAdminPaciente(req, res, path) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user || user.email !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const id = path.split('/')[3];
    
    const [paciente, consultas, documentos, fotos, orientacoes] = await Promise.all([
        fetchSupabase(`pacientes?id=eq.${id}&select=*`),
        fetchSupabase(`consultas?paciente_id=eq.${id}&select=*`),
        fetchSupabase(`documentos?paciente_id=eq.${id}&select=*`),
        fetchSupabase(`fotos?paciente_id=eq.${id}&select=*`),
        fetchSupabase(`orientacoes?paciente_id=eq.${id}&select=*`)
    ]);
    
    return res.json({
        paciente: paciente[0] || null,
        consultas: consultas || [],
        documentos: documentos || [],
        fotos: fotos || [],
        orientacoes: orientacoes || []
    });
}

async function handleEnviarDocumento(req, res) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user || user.email !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const { paciente_id, nome, tipo, url } = await parseBody(req);
    
    const [documento] = await fetchSupabase('documentos', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            nome,
            tipo,
            url,
            data: new Date().toISOString().split('T')[0]
        }])
    });
    
    return res.json(documento);
}

async function handleEnviarOrientacao(req, res) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user || user.email !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const { paciente_id, titulo, conteudo } = await parseBody(req);
    
    const [orientacao] = await fetchSupabase('orientacoes', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            titulo,
            conteudo
        }])
    });
    
    return res.json(orientacao);
}

async function handleAdicionarFoto(req, res) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const user = await verifyToken(token);
    if (!user || user.email !== ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const { paciente_id, tipo, url, tratamento, observacoes } = await parseBody(req);
    
    const [foto] = await fetchSupabase('fotos', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            tipo,
            url,
            tratamento,
            observacoes,
            data: new Date().toISOString().split('T')[0]
        }])
    });
    
    return res.json(foto);
}

// Função para parsear body
async function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}