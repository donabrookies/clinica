    // ============================================
// BACKEND - PRONTUÁRIO ELETRÔNICO
// ============================================

const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configuração do Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const jwtSecret = process.env.JWT_SECRET || 'seu-jwt-secret-super-seguro-aqui';
const adminUser = process.env.ADMIN_USER || 'Admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123';

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ============================================
// FUNÇÕES UTILITÁRIAS
// ============================================

function setCorsHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function verifyToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Token não fornecido');
    }
    const token = authHeader.split(' ')[1];
    return jwt.verify(token, jwtSecret);
}

function verifyAdminToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Token não fornecido');
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, jwtSecret);
    if (!decoded.isAdmin) {
        throw new Error('Acesso não autorizado');
    }
    return decoded;
}

// ============================================
// HANDLER PRINCIPAL
// ============================================

module.exports = async (req, res) => {
    setCorsHeaders(res);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    try {
        const { pathname } = new URL(req.url, `http://${req.headers.host}`);
        console.log(`[${req.method}] ${pathname}`);
        
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', async () => {
            try {
                let data = {};
                if (body) {
                    try {
                        data = JSON.parse(body);
                    } catch (e) {
                        // Não é JSON
                    }
                }
                
                // ============================================
                // ROTAS DE AUTENTICAÇÃO
                // ============================================
                
                // Cadastro de paciente
                if (pathname === '/api/auth/register' && req.method === 'POST') {
                    const { name, cpf, dob, password } = data;
                    
                    // Validação
                    if (!name || !cpf || !dob || !password) {
                        res.status(400).json({ error: 'Todos os campos são obrigatórios' });
                        return;
                    }
                    
                    // Verifica se CPF já existe
                    const { data: existing } = await supabase
                        .from('patients')
                        .select('id')
                        .eq('cpf', cpf.replace(/\D/g, ''))
                        .single();
                    
                    if (existing) {
                        res.status(400).json({ error: 'CPF já cadastrado' });
                        return;
                    }
                    
                    // Hash da senha
                    const passwordHash = await bcrypt.hash(password, 10);
                    
                    // Insere paciente
                    const { data: newPatient, error } = await supabase
                        .from('patients')
                        .insert({
                            name,
                            cpf: cpf.replace(/\D/g, ''),
                            dob,
                            password_hash: passwordHash
                        })
                        .select()
                        .single();
                    
                    if (error) {
                        console.error('Erro ao cadastrar:', error);
                        res.status(500).json({ error: 'Erro ao cadastrar paciente' });
                        return;
                    }
                    
                    res.status(201).json({ message: 'Cadastro realizado com sucesso' });
                    return;
                }
                
                // Login de paciente
                if (pathname === '/api/auth/login' && req.method === 'POST') {
                    const { cpf, password } = data;
                    
                    const { data: patient, error } = await supabase
                        .from('patients')
                        .select('*')
                        .eq('cpf', cpf.replace(/\D/g, ''))
                        .single();
                    
                    if (error || !patient) {
                        res.status(401).json({ error: 'CPF ou senha incorretos' });
                        return;
                    }
                    
                    const validPassword = await bcrypt.compare(password, patient.password_hash);
                    if (!validPassword) {
                        res.status(401).json({ error: 'CPF ou senha incorretos' });
                        return;
                    }
                    
                    const token = jwt.sign(
                        { id: patient.id, cpf: patient.cpf },
                        jwtSecret,
                        { expiresIn: '7d' }
                    );
                    
                    const { password_hash, ...user } = patient;
                    
                    res.status(200).json({ token, user });
                    return;
                }
                
                // Login de admin
                if (pathname === '/api/admin/login' && req.method === 'POST') {
                    const { username, password } = data;
                    
                    if (username !== adminUser || password !== adminPassword) {
                        res.status(401).json({ error: 'Credenciais inválidas' });
                        return;
                    }
                    
                    const token = jwt.sign({ isAdmin: true }, jwtSecret, { expiresIn: '24h' });
                    
                    res.status(200).json({ token });
                    return;
                }
                
                // ============================================
                // ROTAS DO PACIENTE
                // ============================================
                
                // Histórico do paciente
                if (pathname === '/api/patient/history' && req.method === 'GET') {
                    try {
                        const decoded = verifyToken(req.headers.authorization);
                        
                        const { data: history, error } = await supabase
                            .from('consultations')
                            .select('*')
                            .eq('patient_id', decoded.id)
                            .order('date', { ascending: false });
                        
                        if (error) throw error;
                        
                        res.status(200).json(history || []);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // Exames do paciente
                if (pathname === '/api/patient/exams' && req.method === 'GET') {
                    try {
                        const decoded = verifyToken(req.headers.authorization);
                        
                        const { data: exams, error } = await supabase
                            .from('exams')
                            .select('*')
                            .eq('patient_id', decoded.id)
                            .order('created_at', { ascending: false });
                        
                        if (error) throw error;
                        
                        res.status(200).json(exams || []);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // ============================================
                // ROTAS DO ADMIN
                // ============================================
                
                // Listar clientes
                if (pathname === '/api/admin/clients' && req.method === 'GET') {
                    try {
                        verifyAdminToken(req.headers.authorization);
                        
                        const { data: clients, error } = await supabase
                            .from('patients')
                            .select('id, name, cpf, dob, avatar_url, created_at')
                            .order('name');
                        
                        if (error) throw error;
                        
                        res.status(200).json(clients || []);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // Detalhes do cliente
                if (pathname.match(/^\/api\/admin\/clients\/[^/]+$/) && req.method === 'GET') {
                    try {
                        verifyAdminToken(req.headers.authorization);
                        
                        const clientId = pathname.split('/').pop();
                        
                        const { data: client, error } = await supabase
                            .from('patients')
                            .select('id, name, cpf, dob, avatar_url, created_at')
                            .eq('id', clientId)
                            .single();
                        
                        if (error) throw error;
                        
                        res.status(200).json(client);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // Histórico do cliente
                if (pathname.match(/^\/api\/admin\/clients\/[^/]+\/history$/) && req.method === 'GET') {
                    try {
                        verifyAdminToken(req.headers.authorization);
                        
                        const clientId = pathname.split('/')[4];
                        
                        const { data: history, error } = await supabase
                            .from('consultations')
                            .select('*')
                            .eq('patient_id', clientId)
                            .order('date', { ascending: false });
                        
                        if (error) throw error;
                        
                        res.status(200).json(history || []);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // Adicionar consulta
                if (pathname.match(/^\/api\/admin\/clients\/[^/]+\/history$/) && req.method === 'POST') {
                    try {
                        verifyAdminToken(req.headers.authorization);
                        
                        const clientId = pathname.split('/')[4];
                        const { date, time, type, notes } = data;
                        
                        const { data: consultation, error } = await supabase
                            .from('consultations')
                            .insert({
                                patient_id: clientId,
                                date,
                                time,
                                type,
                                notes
                            })
                            .select()
                            .single();
                        
                        if (error) throw error;
                        
                        res.status(201).json(consultation);
                    } catch (error) {
                        res.status(400).json({ error: error.message });
                    }
                    return;
                }
                
                // Exames do cliente
                if (pathname.match(/^\/api\/admin\/clients\/[^/]+\/exams$/) && req.method === 'GET') {
                    try {
                        verifyAdminToken(req.headers.authorization);
                        
                        const clientId = pathname.split('/')[4];
                        
                        const { data: exams, error } = await supabase
                            .from('exams')
                            .select('*')
                            .eq('patient_id', clientId)
                            .order('created_at', { ascending: false });
                        
                        if (error) throw error;
                        
                        res.status(200).json(exams || []);
                    } catch (error) {
                        res.status(401).json({ error: error.message });
                    }
                    return;
                }
                
                // Rota não encontrada
                res.status(404).json({ error: 'Rota não encontrada' });
                
            } catch (error) {
                console.error('Erro interno:', error);
                res.status(500).json({ error: 'Erro interno do servidor' });
            }
        });
        
    } catch (error) {
        console.error('Erro no handler:', error);
        res.status(500).json({ error: 'Erro no servidor' });
    }
};