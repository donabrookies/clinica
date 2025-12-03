// ============================================
// BACKEND COMPLETO - ZERO DEPENDÊNCIAS
// ============================================

// CONFIGURAÇÃO (será preenchida pelas variáveis de ambiente do Vercel)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@clinica.com';
const JWT_SECRET = process.env.JWT_SECRET || 'clinica-secret-key';

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
            
            // Rotas Admin
            case path === '/admin/dashboard' && method === 'GET':
                return await handleAdminDashboard(req, res);
            
            case path === '/admin/pacientes' && method === 'GET':
                return await handleAdminPacientes(req, res);
            
            case path.includes('/admin/paciente/') && method === 'GET':
                return await handleAdminPaciente(req, res, path);
            
            case path === '/admin/novo-paciente' && method === 'POST':
                return await handleAdminNovoPaciente(req, res);
            
            case path === '/admin/enviar-documento' && method === 'POST':
                return await handleEnviarDocumento(req, res);
            
            case path === '/admin/enviar-orientacao' && method === 'POST':
                return await handleEnviarOrientacao(req, res);
            
            case path === '/admin/adicionar-foto' && method === 'POST':
                return await handleAdicionarFoto(req, res);
            
            case path === '/admin/nova-consulta' && method === 'POST':
                return await handleNovaConsulta(req, res);
            
            case path === '/admin/consultas' && method === 'GET':
                return await handleAdminConsultas(req, res);
            
            case path === '/admin/orientacoes' && method === 'GET':
                return await handleAdminOrientacoes(req, res);
            
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
    const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
    const response = await fetch(url, {
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
    const url = `${SUPABASE_URL}/auth/v1/${endpoint}`;
    const response = await fetch(url, {
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

async function verifyAdmin(req) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return { valid: false, error: 'Token ausente' };
    
    const user = await verifyToken(token);
    if (!user) return { valid: false, error: 'Token inválido' };
    
    if (user.email !== ADMIN_EMAIL) {
        return { valid: false, error: 'Acesso negado' };
    }
    
    return { valid: true, user };
}

// ========== HANDLERS ==========

async function handleLogin(req, res) {
    const { email, password } = await parseBody(req);
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }
    
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
        console.error('Login error:', error);
        return res.status(400).json({ error: 'Erro ao fazer login' });
    }
}

async function handleRegister(req, res) {
    const { email, password, nome, telefone, data_nascimento } = await parseBody(req);
    
    if (!email || !password || !nome) {
        return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }
    
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
        console.error('Register error:', error);
        return res.status(400).json({ error: 'Erro ao registrar usuário' });
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
        fetchSupabase(`orientacoes?paciente_id=eq.${pacienteId}&select=*&order=created_at.desc`)
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

// ========== HANDLERS ADMIN ==========

async function handleAdminDashboard(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    // Buscar estatísticas
    const [pacientes, documentos, consultas, fotos] = await Promise.all([
        fetchSupabase('pacientes?select=count'),
        fetchSupabase('documentos?select=count'),
        fetchSupabase('consultas?select=count'),
        fetchSupabase('fotos?select=count')
    ]);
    
    // Atividade recente (últimas orientações)
    const orientacoes = await fetchSupabase('orientacoes?select=*,pacientes(nome)&order=created_at.desc&limit=10');
    
    return res.json({
        totalPacientes: pacientes[0]?.count || 0,
        totalDocumentos: documentos[0]?.count || 0,
        totalConsultas: consultas[0]?.count || 0,
        totalFotos: fotos[0]?.count || 0,
        atividade: orientacoes.map(o => ({
            titulo: `Orientação para ${o.pacientes?.nome || 'Paciente'}`,
            descricao: o.titulo,
            data: new Date(o.created_at).toLocaleDateString('pt-BR')
        }))
    });
}

async function handleAdminPacientes(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const pacientes = await fetchSupabase('pacientes?select=*&order=nome.asc');
    return res.json(pacientes);
}

async function handleAdminPaciente(req, res, path) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const id = path.split('/')[3];
    
    const [paciente, consultas, documentos, fotos, orientacoes] = await Promise.all([
        fetchSupabase(`pacientes?id=eq.${id}&select=*`),
        fetchSupabase(`consultas?paciente_id=eq.${id}&select=*&order=data.desc&limit=10`),
        fetchSupabase(`documentos?paciente_id=eq.${id}&select=*&order=created_at.desc&limit=10`),
        fetchSupabase(`fotos?paciente_id=eq.${id}&select=*&order=data.desc&limit=10`),
        fetchSupabase(`orientacoes?paciente_id=eq.${id}&select=*&order=created_at.desc&limit=10`)
    ]);
    
    return res.json({
        paciente: paciente[0] || null,
        consultas: consultas || [],
        documentos: documentos || [],
        fotos: fotos || [],
        orientacoes: orientacoes || []
    });
}

async function handleAdminNovoPaciente(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const { email, password, nome, telefone, data_nascimento } = await parseBody(req);
    
    if (!email || !password || !nome) {
        return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }
    
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
            message: 'Paciente cadastrado com sucesso!',
            userId: authData.user.id
        });
    } catch (error) {
        console.error('Erro ao criar paciente:', error);
        return res.status(400).json({ error: 'Erro ao cadastrar paciente' });
    }
}

async function handleEnviarDocumento(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const { paciente_id, nome, tipo, url } = await parseBody(req);
    
    if (!paciente_id || !nome || !url) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
    }
    
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
    
    return res.json(documento || { id: Date.now() });
}

async function handleEnviarOrientacao(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const { paciente_id, titulo, conteudo } = await parseBody(req);
    
    if (!paciente_id || !titulo || !conteudo) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
    }
    
    const [orientacao] = await fetchSupabase('orientacoes', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            titulo,
            conteudo,
            lida: false
        }])
    });
    
    return res.json(orientacao || { id: Date.now() });
}

async function handleAdicionarFoto(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const { paciente_id, tipo, url, tratamento, data, observacoes } = await parseBody(req);
    
    if (!paciente_id || !url) {
        return res.status(400).json({ error: 'Preencha os campos obrigatórios' });
    }
    
    const [foto] = await fetchSupabase('fotos', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            tipo,
            url,
            tratamento,
            observacoes,
            data: data || new Date().toISOString().split('T')[0]
        }])
    });
    
    return res.json(foto || { id: Date.now() });
}

async function handleNovaConsulta(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    const { paciente_id, data, tipo, observacoes } = await parseBody(req);
    
    if (!paciente_id || !data || !tipo) {
        return res.status(400).json({ error: 'Preencha os campos obrigatórios' });
    }
    
    const [consulta] = await fetchSupabase('consultas', {
        method: 'POST',
        body: JSON.stringify([{
            paciente_id,
            data,
            tipo,
            observacoes
        }])
    });
    
    return res.json(consulta || { id: Date.now() });
}

async function handleAdminConsultas(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    // Consultas com nome do paciente
    const consultas = await fetchSupabase(`
        consultas?select=*,pacientes(nome)
        &order=data.desc
        &limit=50
    `.replace(/\s+/g, ''));
    
    return res.json(consultas.map(c => ({
        ...c,
        paciente_nome: c.pacientes?.nome
    })));
}

async function handleAdminOrientacoes(req, res) {
    const admin = await verifyAdmin(req);
    if (!admin.valid) return res.status(403).json({ error: admin.error });
    
    // Orientações com nome do paciente
    const orientacoes = await fetchSupabase(`
        orientacoes?select=*,pacientes(nome)
        &order=created_at.desc
        &limit=50
    `.replace(/\s+/g, ''));
    
    return res.json(orientacoes.map(o => ({
        ...o,
        paciente_nome: o.pacientes?.nome
    })));
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