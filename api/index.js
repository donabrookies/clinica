// ============================================
// BACKEND - PRONTUÁRIO ELETRÔNICO (VERSÃO COM MÉDICOS E AGENDAMENTOS)
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

// Cria cliente do Supabase
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

// Função para fazer upload de arquivo para o Supabase Storage
async function uploadFileToStorage(bucket, path, fileBuffer, contentType) {
    try {
        console.log(`Uploading file to ${bucket}/${path}`);
        
        const { data, error } = await supabase
            .storage
            .from(bucket)
            .upload(path, fileBuffer, {
                contentType: contentType,
                upsert: true
            });
        
        if (error) {
            console.error('Upload error:', error);
            throw error;
        }
        
        // Obtém a URL pública
        const { data: urlData } = supabase
            .storage
            .from(bucket)
            .getPublicUrl(path);
        
        console.log('Upload successful, public URL:', urlData.publicUrl);
        return urlData.publicUrl;
    } catch (error) {
        console.error('Error in uploadFileToStorage:', error);
        throw error;
    }
}

// ============================================
// HANDLER PRINCIPAL
// ============================================

module.exports = async (req, res) => {
    // Configura CORS
    setCorsHeaders(res);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    try {
        const url = req.url || '';
        const method = req.method || 'GET';
        
        console.log(`[${method}] ${url}`);
        
        // Coleta o corpo da requisição
        let body = '';
        for await (const chunk of req) {
            body += chunk.toString();
        }
        
        let data = {};
        if (body && body.trim() !== '') {
            try {
                data = JSON.parse(body);
            } catch (e) {
                console.log('Body não é JSON, tratando como raw:', body.substring(0, 100));
            }
        }
        
        // ============================================
        // ROTAS DE AUTENTICAÇÃO
        // ============================================
        
        // CADASTRO DE PACIENTE
        if (url.includes('/api/auth/register') && method === 'POST') {
            console.log('Tentando cadastrar paciente:', data);
            
            const { name, cpf, dob, password, whatsapp } = data;
            
            // Validação básica
            if (!name || !cpf || !dob || !password || !whatsapp) {
                return res.status(400).json({ 
                    error: 'Todos os campos são obrigatórios' 
                });
            }
            
            // Limpa CPF
            const cleanCpf = cpf.replace(/\D/g, '');
            
            // Verifica se CPF já existe
            const { data: existing, error: checkError } = await supabase
                .from('patients')
                .select('id')
                .eq('cpf', cleanCpf)
                .maybeSingle();
            
            if (checkError) {
                console.error('Erro ao verificar CPF:', checkError);
                return res.status(500).json({ error: 'Erro interno do servidor' });
            }
            
            if (existing) {
                return res.status(400).json({ error: 'CPF já cadastrado' });
            }
            
            // Hash da senha
            const passwordHash = await bcrypt.hash(password, 10);
            
            // Insere paciente
            const { data: newPatient, error: insertError } = await supabase
                .from('patients')
                .insert({
                    name: name.trim(),
                    cpf: cleanCpf,
                    dob,
                    password_hash: passwordHash,
                    whatsapp: whatsapp.trim()
                })
                .select()
                .single();
            
            if (insertError) {
                console.error('Erro ao inserir paciente:', insertError);
                return res.status(500).json({ error: 'Erro ao cadastrar paciente' });
            }
            
            return res.status(201).json({ 
                success: true, 
                message: 'Cadastro realizado com sucesso' 
            });
        }
        
        // LOGIN DE PACIENTE
        if (url.includes('/api/auth/login') && method === 'POST') {
            console.log('Tentando login paciente');
            
            const { cpf, password } = data;
            
            if (!cpf || !password) {
                return res.status(400).json({ error: 'CPF e senha são obrigatórios' });
            }
            
            const cleanCpf = cpf.replace(/\D/g, '');
            
            const { data: patient, error } = await supabase
                .from('patients')
                .select('*')
                .eq('cpf', cleanCpf)
                .maybeSingle();
            
            if (error || !patient) {
                console.error('Paciente não encontrado:', error);
                return res.status(401).json({ error: 'CPF ou senha incorretos' });
            }
            
            // Verifica senha
            const validPassword = await bcrypt.compare(password, patient.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'CPF ou senha incorretos' });
            }
            
            // Gera token
            const token = jwt.sign(
                { 
                    id: patient.id, 
                    cpf: patient.cpf,
                    type: 'patient'
                },
                jwtSecret,
                { expiresIn: '7d' }
            );
            
            // Remove senha do retorno
            const { password_hash, ...user } = patient;
            
            return res.status(200).json({ 
                success: true,
                token, 
                user 
            });
        }
        
        // LOGIN DE ADMIN
        if (url.includes('/api/admin/login') && method === 'POST') {
            console.log('Tentando login admin');
            
            const { username, password } = data;
            
            if (username !== adminUser || password !== adminPassword) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }
            
            const token = jwt.sign(
                { isAdmin: true, type: 'admin' }, 
                jwtSecret, 
                { expiresIn: '24h' }
            );
            
            return res.status(200).json({ 
                success: true,
                token 
            });
        }
        
        // ============================================
        // ROTAS DO PACIENTE (PROTEGIDAS)
        // ============================================
        
        // HISTÓRICO DO PACIENTE
        if (url.includes('/api/patient/history') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: history, error } = await supabase
                    .from('consultations')
                    .select('*')
                    .eq('patient_id', decoded.id)
                    .order('date', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(history || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // EXAMES DO PACIENTE
        if (url.includes('/api/patient/exams') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: exams, error } = await supabase
                    .from('exams')
                    .select('*')
                    .eq('patient_id', decoded.id)
                    .order('created_at', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(exams || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // UPLOAD DE AVATAR DO PACIENTE
        if (url.includes('/api/patient/avatar') && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                // Espera receber { avatar: base64String }
                const { avatar } = data;
                
                if (!avatar) {
                    return res.status(400).json({ error: 'Avatar é obrigatório' });
                }
                
                // Verifica se é base64 válido
                if (!avatar.startsWith('data:image/')) {
                    return res.status(400).json({ error: 'Formato de imagem inválido' });
                }
                
                // Extrai o tipo MIME da string base64
                const matches = avatar.match(/^data:image\/(\w+);base64,/);
                if (!matches) {
                    return res.status(400).json({ error: 'Formato base64 inválido' });
                }
                
                const mimeType = matches[1];
                const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');
                
                // Define o caminho no storage
                const fileName = `patient-${decoded.id}-${Date.now()}.${mimeType}`;
                const path = `avatars/${fileName}`;
                
                console.log(`Uploading avatar for patient ${decoded.id}, path: ${path}`);
                
                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                
                // Atualiza o paciente com a nova URL do avatar
                const { data: updatedPatient, error: updateError } = await supabase
                    .from('patients')
                    .update({ avatar_url: publicUrl })
                    .eq('id', decoded.id)
                    .select()
                    .single();
                
                if (updateError) {
                    console.error('Error updating patient:', updateError);
                    throw updateError;
                }
                
                return res.status(200).json({ 
                    success: true, 
                    avatar_url: publicUrl 
                });
            } catch (error) {
                console.error('Error in /api/patient/avatar:', error);
                return res.status(500).json({ 
                    error: 'Erro ao processar imagem: ' + error.message 
                });
            }
        }
        
        // ============================================
        // ROTAS DE MÉDICOS E AGENDAMENTOS (PACIENTE)
        // ============================================
        
        // LISTAR MÉDICOS DISPONÍVEIS
        if (url.includes('/api/doctors') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: doctors, error } = await supabase
                    .from('doctors')
                    .select('*')
                    .order('name');
                
                if (error) throw error;
                
                return res.status(200).json(doctors || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // LISTAR ESPECIALIDADES
        if (url.includes('/api/specialties') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                // Como não temos tabela de especialidades, vamos buscar das descrições dos médicos
                const { data: doctors, error } = await supabase
                    .from('doctors')
                    .select('specialty')
                    .eq('active', true);
                
                if (error) throw error;
                
                // Extrai especialidades únicas
                const specialties = [...new Set(doctors.map(d => d.specialty))].filter(Boolean);
                
                return res.status(200).json(specialties);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // LISTAR DIAS DE TRABALHO DO MÉDICO
        if (url.includes('/api/doctor-work-days') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                const urlParams = new URLSearchParams(url.split('?')[1]);
                const doctor_id = urlParams.get('doctor_id') || data.doctor_id;
                
                if (!doctor_id) {
                    return res.status(400).json({ error: 'ID do médico é obrigatório' });
                }
                
                const { data: workDays, error } = await supabase
                    .from('doctor_work_days')
                    .select('*')
                    .eq('doctor_id', doctor_id)
                    .gte('work_date', new Date().toISOString().split('T')[0])
                    .order('work_date');
                
                if (error) throw error;
                
                return res.status(200).json(workDays || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // LISTAR AGENDAMENTOS DO PACIENTE
        if (url.includes('/api/patient/appointments') && method === 'GET') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { data: appointments, error } = await supabase
                    .from('appointments')
                    .select(`
                        *,
                        doctors (
                            name,
                            specialty
                        )
                    `)
                    .eq('patient_id', decoded.id)
                    .gte('appointment_date', new Date().toISOString().split('T')[0])
                    .order('appointment_date')
                    .order('appointment_time');
                
                if (error) throw error;
                
                return res.status(200).json(appointments || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // CRIAR AGENDAMENTO
        if (url.includes('/api/appointments') && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const { doctor_id, appointment_date, appointment_time, notes, whatsapp } = data;
                
                if (!doctor_id || !appointment_date || !appointment_time || !whatsapp) {
                    return res.status(400).json({ error: 'Médico, data, horário e WhatsApp são obrigatórios' });
                }
                
                // Verifica se o médico trabalha nesse dia e horário
                const { data: workDay, error: workDayError } = await supabase
                    .from('doctor_work_days')
                    .select('*')
                    .eq('doctor_id', doctor_id)
                    .eq('work_date', appointment_date)
                    .single();
                
                if (workDayError || !workDay) {
                    return res.status(400).json({ error: 'Médico não trabalha neste dia' });
                }
                
                // Converte horários para comparar
                const appointmentTime = new Date(`1970-01-01T${appointment_time}`);
                const startTime = new Date(`1970-01-01T${workDay.start_time}`);
                const endTime = new Date(`1970-01-01T${workDay.end_time}`);
                
                if (appointmentTime < startTime || appointmentTime >= endTime) {
                    return res.status(400).json({ error: 'Horário fora do expediente do médico' });
                }
                
                // Verifica se já existe agendamento no mesmo horário
                const { data: existingAppointment, error: checkError } = await supabase
                    .from('appointments')
                    .select('id')
                    .eq('doctor_id', doctor_id)
                    .eq('appointment_date', appointment_date)
                    .eq('appointment_time', appointment_time)
                    .eq('status', 'agendado')
                    .maybeSingle();
                
                if (existingAppointment) {
                    return res.status(400).json({ error: 'Horário já agendado' });
                }
                
                // Cria o agendamento
                const { data: appointment, error: insertError } = await supabase
                    .from('appointments')
                    .insert({
                        patient_id: decoded.id,
                        doctor_id,
                        appointment_date,
                        appointment_time,
                        notes: notes || '',
                        whatsapp: whatsapp.trim(),
                        status: 'agendado'
                    })
                    .select()
                    .single();
                
                if (insertError) throw insertError;
                
                return res.status(201).json(appointment);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // CANCELAR AGENDAMENTO
        if (url.match(/\/api\/appointments\/[^/]+\/cancel$/) && method === 'POST') {
            try {
                const decoded = verifyToken(req.headers.authorization);
                
                const appointmentId = url.split('/')[3];
                
                // Primeiro verifica se o agendamento existe e pertence ao paciente
                const { data: appointment, error: fetchError } = await supabase
                    .from('appointments')
                    .select('*')
                    .eq('id', appointmentId)
                    .eq('patient_id', decoded.id)
                    .single();
                
                if (fetchError || !appointment) {
                    return res.status(404).json({ error: 'Agendamento não encontrado' });
                }
                
                // Cancela o agendamento
                const { error } = await supabase
                    .from('appointments')
                    .update({ status: 'cancelado' })
                    .eq('id', appointmentId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(500).json({ error: 'Erro ao cancelar agendamento' });
            }
        }
        
        // ============================================
        // ROTAS DO ADMIN (PROTEGIDAS)
        // ============================================
        
        // LISTAR TODOS OS CLIENTES
        if (url.includes('/api/admin/clients') && method === 'GET' && !url.includes('/clients/')) {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { data: clients, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, whatsapp, created_at')
                    .order('name');
                
                if (error) throw error;
                
                return res.status(200).json(clients || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // DETALHES DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const clientId = url.split('/').pop();
                
                const { data: client, error } = await supabase
                    .from('patients')
                    .select('id, name, cpf, dob, avatar_url, whatsapp, created_at')
                    .eq('id', clientId)
                    .single();
                
                if (error) throw error;
                
                return res.status(200).json(client);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // HISTÓRICO DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+\/history$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                
                const { data: history, error } = await supabase
                    .from('consultations')
                    .select('*')
                    .eq('patient_id', clientId)
                    .order('date', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(history || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ADICIONAR CONSULTA
        if (url.match(/\/api\/admin\/clients\/[^/]+\/history$/) && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                const { date, time, type, notes } = data;
                
                if (!date || !type) {
                    return res.status(400).json({ error: 'Data e tipo são obrigatórios' });
                }
                
                const { data: consultation, error } = await supabase
                    .from('consultations')
                    .insert({
                        patient_id: clientId,
                        date,
                        time: time || '00:00',
                        type,
                        notes: notes || ''
                    })
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(201).json(consultation);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // EXAMES DE UM CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+\/exams$/) && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                
                const { data: exams, error } = await supabase
                    .from('exams')
                    .select('*')
                    .eq('patient_id', clientId)
                    .order('created_at', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(exams || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ADICIONAR EXAME (com upload de arquivo base64)
        if (url.match(/\/api\/admin\/clients\/[^/]+\/exams$/) && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                const { type, file } = data; // file é base64
                
                if (!type || !file) {
                    return res.status(400).json({ error: 'Tipo e arquivo são obrigatórios' });
                }
                
                // Verifica se é base64 válido
                if (!file.startsWith('data:application/pdf;base64,')) {
                    return res.status(400).json({ error: 'Formato de arquivo inválido. Apenas PDF são aceitos.' });
                }
                
                // Converte base64 para buffer
                const base64Data = file.replace(/^data:application\/pdf;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');
                
                // Define o caminho no storage
                const fileName = `${type.replace(/\s+/g, '-').toLowerCase()}-${clientId}-${Date.now()}.pdf`;
                const path = `exams/${fileName}`;
                
                console.log(`Uploading exam for client ${clientId}, path: ${path}`);
                
                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, 'application/pdf');
                
                // Insere o exame no banco
                const { data: exam, error: insertError } = await supabase
                    .from('exams')
                    .insert({
                        patient_id: clientId,
                        type,
                        file_url: publicUrl
                    })
                    .select()
                    .single();
                
                if (insertError) throw insertError;
                
                return res.status(201).json(exam);
            } catch (error) {
                console.error('Error uploading exam:', error);
                return res.status(500).json({ error: 'Erro ao enviar exame: ' + error.message });
            }
        }
        
        // UPLOAD DE AVATAR DO CLIENTE PELO ADMIN
        if (url.match(/\/api\/admin\/clients\/[^/]+\/avatar$/) && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const parts = url.split('/');
                const clientId = parts[parts.length - 2];
                const { avatar } = data;
                
                if (!avatar) {
                    return res.status(400).json({ error: 'Avatar é obrigatório' });
                }
                
                // Verifica se é base64 válido
                if (!avatar.startsWith('data:image/')) {
                    return res.status(400).json({ error: 'Formato de imagem inválido' });
                }
                
                // Extrai o tipo MIME da string base64
                const matches = avatar.match(/^data:image\/(\w+);base64,/);
                if (!matches) {
                    return res.status(400).json({ error: 'Formato base64 inválido' });
                }
                
                const mimeType = matches[1];
                const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                const buffer = Buffer.from(base64Data, 'base64');
                
                // Define o caminho no storage
                const fileName = `patient-${clientId}-${Date.now()}.${mimeType}`;
                const path = `avatars/${fileName}`;
                
                console.log(`Uploading avatar for client ${clientId}, path: ${path}`);
                
                // Faz upload
                const publicUrl = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                
                // Atualiza o paciente com a nova URL do avatar
                const { data: updatedPatient, error: updateError } = await supabase
                    .from('patients')
                    .update({ avatar_url: publicUrl })
                    .eq('id', clientId)
                    .select()
                    .single();
                
                if (updateError) {
                    console.error('Error updating patient:', updateError);
                    throw updateError;
                }
                
                return res.status(200).json({ 
                    success: true, 
                    avatar_url: publicUrl 
                });
            } catch (error) {
                console.error('Error in /api/admin/clients/avatar:', error);
                return res.status(500).json({ 
                    error: 'Erro ao processar imagem: ' + error.message 
                });
            }
        }
        
        // ============================================
        // ROTAS DE MÉDICOS (ADMIN)
        // ============================================
        
        // LISTAR TODOS OS MÉDICOS
        if (url.includes('/api/admin/doctors') && method === 'GET' && !url.includes('/doctors/')) {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { data: doctors, error } = await supabase
                    .from('doctors')
                    .select('*')
                    .order('name');
                
                if (error) throw error;
                
                return res.status(200).json(doctors || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // CRIAR MÉDICO
        if (url.includes('/api/admin/doctors') && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { name, specialty, description, phone, email, avatar } = data;
                
                if (!name || !specialty) {
                    return res.status(400).json({ error: 'Nome e especialidade são obrigatórios' });
                }
                
                let avatar_url = null;
                if (avatar) {
                    // Verifica se é base64 válido
                    if (!avatar.startsWith('data:image/')) {
                        return res.status(400).json({ error: 'Formato de imagem inválido' });
                    }
                    
                    const matches = avatar.match(/^data:image\/(\w+);base64,/);
                    if (!matches) {
                        return res.status(400).json({ error: 'Formato base64 inválido' });
                    }
                    
                    const mimeType = matches[1];
                    const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                    const buffer = Buffer.from(base64Data, 'base64');
                    
                    const fileName = `doctor-${Date.now()}.${mimeType}`;
                    const path = `doctors/${fileName}`;
                    
                    avatar_url = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                }
                
                const { data: doctor, error } = await supabase
                    .from('doctors')
                    .insert({
                        name,
                        specialty,
                        description: description || '',
                        phone: phone || '',
                        email: email || '',
                        avatar_url,
                        active: true
                    })
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(201).json(doctor);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // ATUALIZAR MÉDICO
        if (url.match(/\/api\/admin\/doctors\/[^/]+$/) && method === 'PUT') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const doctorId = url.split('/').pop();
                const { name, specialty, description, phone, email, active, avatar } = data;
                
                let updateData = {
                    name,
                    specialty,
                    description,
                    phone,
                    email,
                    active
                };
                
                if (avatar) {
                    // Verifica se é base64 válido
                    if (!avatar.startsWith('data:image/')) {
                        return res.status(400).json({ error: 'Formato de imagem inválido' });
                    }
                    
                    const matches = avatar.match(/^data:image\/(\w+);base64,/);
                    if (!matches) {
                        return res.status(400).json({ error: 'Formato base64 inválido' });
                    }
                    
                    const mimeType = matches[1];
                    const base64Data = avatar.replace(/^data:image\/\w+;base64,/, '');
                    const buffer = Buffer.from(base64Data, 'base64');
                    
                    const fileName = `doctor-${doctorId}-${Date.now()}.${mimeType}`;
                    const path = `doctors/${fileName}`;
                    
                    const avatar_url = await uploadFileToStorage('uploads', path, buffer, `image/${mimeType}`);
                    updateData.avatar_url = avatar_url;
                }
                
                const { data: doctor, error } = await supabase
                    .from('doctors')
                    .update(updateData)
                    .eq('id', doctorId)
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(200).json(doctor);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // DELETAR MÉDICO
        if (url.match(/\/api\/admin\/doctors\/[^/]+$/) && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const doctorId = url.split('/').pop();
                
                const { error } = await supabase
                    .from('doctors')
                    .delete()
                    .eq('id', doctorId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // ============================================
        // ROTAS DE DIAS DE TRABALHO (ADMIN)
        // ============================================
        
        // LISTAR DIAS DE TRABALHO
        if (url.includes('/api/admin/work-days') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { data: workDays, error } = await supabase
                    .from('doctor_work_days')
                    .select(`
                        *,
                        doctors (
                            name,
                            specialty
                        )
                    `)
                    .order('work_date', { ascending: false });
                
                if (error) throw error;
                
                return res.status(200).json(workDays || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ADICIONAR DIA DE TRABALHO
        if (url.includes('/api/admin/doctor-work-days') && method === 'POST') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const { doctor_id, work_date, start_time, end_time } = data;
                
                if (!doctor_id || !work_date || !start_time || !end_time) {
                    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
                }
                
                // Verifica se já existe dia de trabalho para este médico na mesma data
                const { data: existing, error: checkError } = await supabase
                    .from('doctor_work_days')
                    .select('id')
                    .eq('doctor_id', doctor_id)
                    .eq('work_date', work_date)
                    .maybeSingle();
                
                if (existing) {
                    return res.status(400).json({ error: 'Já existe um dia de trabalho para esta data' });
                }
                
                const { data: workDay, error } = await supabase
                    .from('doctor_work_days')
                    .insert({
                        doctor_id,
                        work_date,
                        start_time,
                        end_time
                    })
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(201).json(workDay);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // DELETAR DIA DE TRABALHO
        if (url.match(/\/api\/admin\/doctor-work-days\/[^/]+$/) && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const workDayId = url.split('/').pop();
                
                const { error } = await supabase
                    .from('doctor_work_days')
                    .delete()
                    .eq('id', workDayId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ============================================
        // ROTAS DE AGENDAMENTOS (ADMIN)
        // ============================================
        
        // LISTAR TODOS OS AGENDAMENTOS
        if (url.includes('/api/admin/appointments') && method === 'GET') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const urlParams = new URLSearchParams(url.split('?')[1]);
                const status = urlParams.get('status');
                const date = urlParams.get('date');
                
                let query = supabase
                    .from('appointments')
                    .select(`
                        *,
                        patients (
                            name,
                            cpf,
                            whatsapp
                        ),
                        doctors (
                            name,
                            specialty
                        )
                    `);
                
                if (status) {
                    query = query.eq('status', status);
                }
                
                if (date) {
                    query = query.eq('appointment_date', date);
                }
                
                query = query.order('appointment_date')
                           .order('appointment_time');
                
                const { data: appointments, error } = await query;
                
                if (error) throw error;
                
                return res.status(200).json(appointments || []);
            } catch (error) {
                return res.status(401).json({ error: error.message });
            }
        }
        
        // ATUALIZAR STATUS DO AGENDAMENTO
        if (url.match(/\/api\/admin\/appointments\/[^/]+\/status$/) && method === 'PUT') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const appointmentId = url.split('/')[3];
                const { status } = data;
                
                if (!status) {
                    return res.status(400).json({ error: 'Status é obrigatório' });
                }
                
                const { data: appointment, error } = await supabase
                    .from('appointments')
                    .update({ status })
                    .eq('id', appointmentId)
                    .select()
                    .single();
                
                if (error) throw error;
                
                return res.status(200).json(appointment);
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // ============================================
        // ROTAS DE EXCLUSÃO (ADMIN)
        // ============================================
        
        // DELETAR CONSULTA
        if (url.match(/\/api\/admin\/history\/[^/]+$/) && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const historyId = url.split('/').pop();
                
                const { error } = await supabase
                    .from('consultations')
                    .delete()
                    .eq('id', historyId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // DELETAR EXAME
        if (url.match(/\/api\/admin\/exams\/[^/]+$/) && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const examId = url.split('/').pop();
                
                const { error } = await supabase
                    .from('exams')
                    .delete()
                    .eq('id', examId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // DELETAR CLIENTE
        if (url.match(/\/api\/admin\/clients\/[^/]+$/) && method === 'DELETE') {
            try {
                verifyAdminToken(req.headers.authorization);
                
                const clientId = url.split('/').pop();
                
                const { error } = await supabase
                    .from('patients')
                    .delete()
                    .eq('id', clientId);
                
                if (error) throw error;
                
                return res.status(200).json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: error.message });
            }
        }
        
        // ROTA DE TESTE
        if (url === '/api/test' || url === '/api') {
            return res.status(200).json({ 
                message: 'API está funcionando',
                timestamp: new Date().toISOString(),
                environment: 'production'
            });
        }
        
        // ROTA RAIZ - Health Check
        if (url === '/' && method === 'GET') {
            return res.status(200).json({ 
                message: 'API do Prontuário Eletrônico',
                version: '2.0.0',
                status: 'online',
                timestamp: new Date().toISOString(),
                features: {
                    auth: true,
                    patients: true,
                    doctors: true,
                    appointments: true,
                    exams: true,
                    consultations: true
                },
                routes: {
                    auth: {
                        register: 'POST /api/auth/register',
                        login: 'POST /api/auth/login',
                        adminLogin: 'POST /api/admin/login'
                    },
                    patient: {
                        history: 'GET /api/patient/history',
                        exams: 'GET /api/patient/exams',
                        avatar: 'POST /api/patient/avatar',
                        doctors: 'GET /api/doctors',
                        specialties: 'GET /api/specialties',
                        appointments: 'GET /api/patient/appointments',
                        createAppointment: 'POST /api/appointments',
                        cancelAppointment: 'POST /api/appointments/:id/cancel'
                    },
                    admin: {
                        clients: 'GET /api/admin/clients',
                        clientDetail: 'GET /api/admin/clients/:id',
                        clientHistory: 'GET /api/admin/clients/:id/history',
                        addHistory: 'POST /api/admin/clients/:id/history',
                        clientExams: 'GET /api/admin/clients/:id/exams',
                        addExam: 'POST /api/admin/clients/:id/exams',
                        clientAvatar: 'POST /api/admin/clients/:id/avatar',
                        doctors: 'GET /api/admin/doctors',
                        createDoctor: 'POST /api/admin/doctors',
                        updateDoctor: 'PUT /api/admin/doctors/:id',
                        deleteDoctor: 'DELETE /api/admin/doctors/:id',
                        workDays: 'GET /api/admin/work-days',
                        addWorkDay: 'POST /api/admin/doctor-work-days',
                        deleteWorkDay: 'DELETE /api/admin/doctor-work-days/:id',
                        appointments: 'GET /api/admin/appointments',
                        updateAppointmentStatus: 'PUT /api/admin/appointments/:id/status',
                        deleteHistory: 'DELETE /api/admin/history/:id',
                        deleteExam: 'DELETE /api/admin/exams/:id',
                        deleteClient: 'DELETE /api/admin/clients/:id'
                    }
                }
            });
        }
        
        // TESTE DE CONEXÃO COM SUPABASE
        if (url === '/api/health' && method === 'GET') {
            try {
                // Testa conexão com Supabase
                const { data, error } = await supabase
                    .from('patients')
                    .select('count')
                    .limit(1);
                
                return res.status(200).json({
                    status: 'healthy',
                    supabase: error ? 'connection_error' : 'connected',
                    timestamp: new Date().toISOString(),
                    environment: {
                        supabase_url: supabaseUrl ? 'configured' : 'missing',
                        jwt_secret: jwtSecret ? 'configured' : 'default',
                        admin_user: adminUser ? 'configured' : 'default'
                    }
                });
            } catch (error) {
                return res.status(500).json({
                    status: 'unhealthy',
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        }
        
        // ROTA NÃO ENCONTRADA
        console.log('Rota não encontrada:', url);
        return res.status(404).json({ 
            error: 'Rota não encontrada',
            path: url,
            method: method
        });
        
    } catch (error) {
        console.error('Erro interno do servidor:', error);
        return res.status(500).json({ 
            error: 'Erro interno do servidor',
            message: error.message
        });
    }
};