import 'dotenv/config';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { db } from "./db/index.js";
import { users,todos } from "./db/schema.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { setCookie } from 'hono/cookie';
import { getCookie } from 'hono/cookie';
import { json } from 'drizzle-orm/gel-core';
import { serveStatic } from '@hono/node-server/serve-static';
 
const app = new Hono();

app.use('/*', serveStatic({ root: './public' }));

app.get('/', (c) => {
  return c.html('<h1>Tim Pengembang</h1><h2>Muhammad Fathi Akyel Malino</h2>');
});

app.post('/api/register', async (c) => {
  try {
    const { username, password } = await c.req.json();
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await db.insert(users)
      .values({ username, password: hashedPassword })
      .returning({ id: users.id, username: users.username });
 
    return c.json({ success: true, data: newUser[0] }, 201);
  } catch (error) {
    return c.json({ success: false, message: 'Registrasi gagal' }, 400);
  }
});

app.post('/api/login', async (c) => {
    const { username, password } = await c.req.json();
    const user = await db.query.users.findFirst({ where: (users, { eq }) => eq(users.username, username) });
 
    if (!user) return c.json({ success: false, message: 'Username atau password salah' }, 401);
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return c.json({ success: false, message: 'Username atau password salah' }, 401);
 
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    setCookie(c, 'token', token, { httpOnly: true, sameSite: 'Lax', maxAge: 3600 });
    
    return c.json({ success: true, message: 'Login berhasil' });
});

app.get('/api/me', (c) => {
const token = getCookie(c, 'token');
    if (!token) return c.json({ success: false, message: 'Unauthorized' }, 401);
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        
    return c.json({ success: true, data: user });
    } catch (error) {
        return c.json({ success: false, message: 'Unauthorized' }, 401);
    }
});

app.post('/logout', (c) => {
  setCookie(c, 'token', '', { maxAge: -1 });
  return c.json({ success: true, message: 'Logout Berhasil' });
});

app.post('/api/todos', async (c) => {
  const token = getCookie(c, 'token');
    if (!token) return c.json({ success: false, message: 'Unauthorized' }, 401);
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
         const { note } = await c.req.json();
    const newTodo = await db.insert(todos)
        .values({ note, userId: user.id })
        .returning();
    return c.json({ success: true, data: newTodo[0] }, 201);
    } catch (error) {
        return c.json({ success: false, message: 'Unauthorized' }, 401);
    }
});

app.get('/api/todos', async (c) => {
  const token = getCookie(c, 'token');
    if (!token) return c.json({ success: false, message: 'Unauthorized' }, 401);
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        const userTodos = await db.query.todos.findMany({
        where: (todos, { eq }) => eq(todos.userId, user.id)
    });
    return c.json({ success: true, data: userTodos });
    } catch (error) {
        return c.json({ success: false, message: 'Unauthorized' }, 401);
    }
});

 
if (process.env.VERCEL) {
  console.log('Running on Vercel');
  globalThis.app = app;
} else {
  const port = 5000;
  console.log(`✅ Server is running on http://localhost:${port}`);
  serve({
    fetch: app.fetch,
    port,
  });
}