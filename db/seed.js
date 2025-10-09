import 'dotenv/config';
import { db } from './index.js';
import bcrypt from 'bcryptjs';
import { todos, users } from './schema.js';
 
async function seed() {
  console.log('Seeding database...');
 
  await db.delete(todos);
  await db.delete(users);
 
 const plainPassword = 'password123';
  const hashedPassword = await bcrypt.hash(plainPassword, 10);

  const user1 = await db
    .insert(users)
    .values({
      username: 'andi',
      password: hashedPassword,
    })
    .returning();
 
  await db.insert(todos).values([
    { note: 'Belajar Drizzle ORM', userId: user1[0].id },
    { note: 'Membuat API dengan Hono', userId: user1[0].id },
  ]);
 
  console.log('✅ Seeding completed!');
  process.exit(0);
}
 
seed().catch((err) => {
  console.error('❌ Seeding failed:', err);
  process.exit(1);
});