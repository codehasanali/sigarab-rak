import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { authMiddleware } from './libs/authMiddleware';
import cloudinary from './libs/cloudinary';
import { Readable } from 'stream';

const prisma = new PrismaClient();
const app = new Hono();

app.get('/', (c) => {
  return c.text('Hello Hono!');
});

app.post('/register', async (c) => {
  try {
    // FormData ile veri al
    const formData = await c.req.formData();
    const email = formData.get('email')?.toString();
    const password = formData.get('password')?.toString();
    const profileImage = formData.get('profileImage') as File;

    if (!email || !password) {
      return c.json({ message: 'Email and password are required' }, 400);
    }

    // Profil resmini Cloudinary'ye yükle
    let imageUrl: string | undefined;
    if (profileImage) {
      try {
        // File nesnesini doğrudan Buffer'a çevir
        const buffer = Buffer.from(await profileImage.arrayBuffer());

        // Cloudinary'ye yükle
        const uploadResult = await new Promise<any>((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            { folder: 'profile_images' },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );

          uploadStream.end(buffer);
        });

        imageUrl = uploadResult.secure_url;
      } catch (uploadError) {
        console.error('Error uploading image:', uploadError);
        return c.json({ message: 'Error uploading profile image' }, 500);
      }
    }

    // Şifreyi hashle
    const hashedPassword = await bcrypt.hash(password, 10);

    // Kullanıcıyı veritabanına kaydet
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        imageUrl,
      },
    });

    // JWT token oluştur
    const token = jwt.sign(
      { id: user.id, email: user.email },
      "hasanali",
      { expiresIn: '1h' }
    );

    return c.json({ user: { id: user.id, email: user.email, imageUrl: user.imageUrl }, token }, 201);
  } catch (error) {
    console.error('Error during registration:', error);
    return c.json({ message: 'An error occurred during registration' }, 500);
  }
});





app.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json();
    if (!email || !password) {
      return c.json({ message: 'Email and password are required' }, 400);
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return c.json({ message: 'Invalid email or password' }, 401);
    }
    const token = jwt.sign({ id: user.id, email: user.email },"hasanali", { expiresIn: '1h' });
    return c.json({ token });

  } catch (error) {
    console.error('Error during login:', error);
    return c.json({ message: 'An error occurred during login' }, 500);
  }
});


app.get('/profile', authMiddleware, async (c) => {
  try {
    // `authMiddleware` tarafından JWT'den alınan kullanıcı bilgisi
    const user = c.get('user') as { id: string; email: string };

    // Kullanıcı ID'si geçerli mi kontrol et
    if (!user || !user.id) {
      return c.json({ message: 'User not found' }, 404);
    }

    // Kullanıcı profilini veritabanından al
    const userProfile = await prisma.user.findUnique({
      where: { id: user.id },
      select: { id: true, email: true }, // Diğer profil bilgilerini ekleyebilirsiniz
    });

    // Kullanıcı veritabanında bulunamadıysa
    if (!userProfile) {
      return c.json({ message: 'User not found' }, 404);
    }

    // Kullanıcı profilini döndür
    return c.json({ user: userProfile });

  } catch (error) {
    console.error('Error fetching profile:', error);
    return c.json({ message: 'An error occurred fetching profile' }, 500);
  }
});


const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
