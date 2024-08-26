const express = require('express'); // เรียกใช้ Express framework เพื่อสร้างเว็บแอปพลิเคชัน
const mysql = require('mysql2'); // เรียกใช้ไลบรารี MySQL2 สำหรับเชื่อมต่อกับฐานข้อมูล MySQL
const helmet = require('helmet'); // เพิ่ม helmet เพื่อป้องกันการโจมตีผ่าน HTTP headers
const rateLimit = require('express-rate-limit'); // เพิ่ม rate limiting เพื่อป้องกันการโจมตีแบบ DDoS
const bcrypt = require('bcrypt'); // ใช้ bcrypt สำหรับการเข้ารหัสรหัสผ่าน
const https = require('https'); // เรียกใช้โมดูล https เพื่อสร้างเซิร์ฟเวอร์ HTTPS
const fs = require('fs'); // ใช้โมดูล fs สำหรับอ่านไฟล์ในระบบไฟล์
require('dotenv').config(); // โหลด environment variables จากไฟล์ .env เพื่อใช้ในโปรแกรม

const app = express(); // สร้าง instance ของ Express เพื่อใช้กำหนดค่าต่างๆ สำหรับแอปพลิเคชัน
const port = process.env.PORT || 3000; // กำหนดหมายเลข port ที่เซิร์ฟเวอร์จะรับฟังการเชื่อมต่อ โดยรับค่าจาก .env หรือใช้ค่าเริ่มต้นเป็น 3000

// ใช้ Helmet เพื่อเพิ่มความปลอดภัยให้กับแอปพลิเคชัน โดยเพิ่ม headers ที่ช่วยป้องกันการโจมตี
app.use(helmet());

// ตั้งค่า Rate Limiting เพื่อจำกัดจำนวนคำขอที่สามารถทำได้ในช่วงเวลา 15 นาที (ป้องกันการโจมตีแบบ DDoS)
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // ระยะเวลา 15 นาที
    max: 100, // จำกัดจำนวนคำขอที่ 100 ครั้งต่อ IP ต่อ 15 นาที
});
app.use(generalLimiter); // นำ Rate Limiting ไปใช้กับทุกคำขอที่เข้ามาในแอปพลิเคชัน

// ใช้ middleware เพื่อแปลงข้อมูล JSON ที่รับมาจาก client ให้เป็น JavaScript object
app.use(express.json());

// ใช้ middleware เพื่อแปลงข้อมูลที่ส่งมาในฟอร์มแบบ URL-encoded ให้เป็น JavaScript object
app.use(express.urlencoded({ extended: true }));

// สร้างการเชื่อมต่อกับฐานข้อมูล MySQL โดยใช้ข้อมูลจาก environment variables
const db = mysql.createConnection({
    host: process.env.DB_HOST, // กำหนดชื่อโฮสต์ของฐานข้อมูล รับค่าจาก environment variables
    user: process.env.DB_USER, // กำหนดชื่อผู้ใช้สำหรับเข้าถึงฐานข้อมูล รับค่าจาก environment variables
    password: process.env.DB_PASSWORD, // กำหนดรหัสผ่านสำหรับเข้าถึงฐานข้อมูล รับค่าจาก environment variables
    database: process.env.DB_NAME, // กำหนดชื่อฐานข้อมูลที่ต้องการเชื่อมต่อ รับค่าจาก environment variables
    ssl: { rejectUnauthorized: false } // ปิดการตรวจสอบใบรับรอง SSL เพื่อหลีกเลี่ยงข้อผิดพลาดในการเชื่อมต่อ (ใช้สำหรับการพัฒนา)
});

db.connect((err) => { // ทำการเชื่อมต่อกับฐานข้อมูล
    if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
        console.error('ไม่สามารถเชื่อมต่อฐานข้อมูลได้:', err); // ถ้าเกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล จะแสดงข้อความนี้
        process.exit(1); // ยุติการทำงานของโปรแกรมทันทีถ้าเชื่อมต่อฐานข้อมูลไม่ได้
    }
    console.log('เชื่อมต่อฐานข้อมูลสำเร็จ'); // ถ้าการเชื่อมต่อฐานข้อมูลสำเร็จ จะแสดงข้อความนี้
});

// ตั้งค่า Rate Limiting สำหรับการเข้าสู่ระบบ เพื่อจำกัดการพยายามเข้าสู่ระบบ
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // ระยะเวลา 15 นาที
    max: 10, // จำกัดการพยายามเข้าสู่ระบบที่ 10 ครั้งต่อ IP ต่อ 15 นาที
    message: { // ข้อความที่จะส่งกลับเมื่อพยายามเข้าสู่ระบบเกินจำนวนครั้งที่กำหนด
        status: false,
        message: "พยายามเข้าสู่ระบบเกินจำนวนครั้งที่กำหนด โปรดลองใหม่อีกครั้งในภายหลัง"
    }
});

// กำหนดเส้นทาง (route) สำหรับการเข้าสู่ระบบ
app.post('/login', loginLimiter, function(req, res) { // ใช้ loginLimiter เฉพาะกับคำขอเข้าสู่ระบบ
    const { username, password } = req.body; // ดึงข้อมูลชื่อผู้ใช้และรหัสผ่านจาก request body
    const sql = "SELECT * FROM customer WHERE username = ? AND isActive = 1"; // สร้างคำสั่ง SQL เพื่อดึงข้อมูลผู้ใช้ที่ยังใช้งานอยู่เท่านั้น
    db.query(sql, [username], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับชื่อผู้ใช้ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดในการเชื่อมต่อหรือไม่
            console.error('ข้อผิดพลาดในการเข้าสู่ระบบ:', err); // แสดงข้อความข้อผิดพลาดถ้ามี
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        if (result.length > 0) { // ตรวจสอบว่าพบข้อมูลผู้ใช้หรือไม่
            const customer = result[0]; // ดึงข้อมูลผู้ใช้จากผลลัพธ์ที่ได้
            bcrypt.compare(password, customer.password, function(err, match) { // ตรวจสอบรหัสผ่านที่เข้ารหัสด้วย bcrypt ว่าตรงกับข้อมูลในฐานข้อมูลหรือไม่
                if (match) { // ถ้ารหัสผ่านถูกต้อง
                    customer['message'] = "เข้าสู่ระบบสำเร็จ"; // กำหนดข้อความยืนยันการเข้าสู่ระบบสำเร็จ
                    customer['status'] = true; // กำหนดสถานะเป็น true เพื่อบอกว่าการเข้าสู่ระบบสำเร็จ
                    res.send(customer); // ส่งข้อมูลผู้ใช้กลับไปยัง client
                } else { // ถ้ารหัสผ่านไม่ถูกต้อง
                    res.send({ "message": "กรุณาระบุรหัสผ่านใหม่อีกครั้ง", "status": false }); // ส่งข้อความแจ้งว่ารหัสผ่านไม่ถูกต้อง
                }
            });
        } else { // ถ้าไม่พบข้อมูลผู้ใช้ในฐานข้อมูล
            res.send({ "message": "กรุณาระบุรหัสผ่านใหม่อีกครั้ง", "status": false }); // ส่งข้อความแจ้งว่ารหัสผ่านไม่ถูกต้อง
        }
    });
});

// กำหนดเส้นทาง (route) สำหรับการเพิ่มข้อมูลสินค้าใหม่ลงในฐานข้อมูล
app.post('/product', function(req, res) {
    const { productName, productDetail, price, cost, quantity } = req.body; // ดึงข้อมูลสินค้า เช่น ชื่อสินค้า รายละเอียด ราคา ต้นทุน และจำนวนจาก request body
    const sql = "INSERT INTO product (productName, productDetail, price, cost, quantity) VALUES (?, ?, ?, ?, ?)"; // สร้างคำสั่ง SQL เพื่อเพิ่มข้อมูลสินค้าใหม่ลงในฐานข้อมูล โดยใช้ placeholders เพื่อป้องกัน SQL Injection
    db.query(sql, [productName, productDetail, price, cost, quantity], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับข้อมูลสินค้าที่จะถูกแทนที่ใน placeholders ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('ข้อผิดพลาดในการบันทึกข้อมูล:', err); // แสดงข้อความข้อผิดพลาดถ้ามี
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการบันทึกข้อมูล', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        res.send({ 'message': 'บันทึกข้อมูลสำเร็จ', 'status': true }); // ส่งข้อความยืนยันว่าบันทึกข้อมูลสำเร็จกลับไปยัง client
    });
});

// กำหนดเส้นทาง (route) สำหรับการดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ productID
app.get('/product/:id', function(req, res) {
    const productID = req.params.id; // ดึง productID จากพารามิเตอร์ใน URL
    const sql = "SELECT * FROM product WHERE productID = ?"; // สร้างคำสั่ง SQL เพื่อดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ productID
    db.query(sql, [productID], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่า productID ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('ข้อผิดพลาดในการดึงข้อมูล:', err); // แสดงข้อความข้อผิดพลาดถ้ามี
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการดึงข้อมูล', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        res.send(result); // ส่งผลลัพธ์จากการดึงข้อมูลสินค้า (ข้อมูลทั้งหมดของสินค้า) กลับไปยัง client
    });
});

// กำหนดเส้นทาง (route) สำหรับการสร้างผู้ใช้ใหม่พร้อมเข้ารหัสรหัสผ่าน
app.post('/register', function(req, res) {
    const { username, password } = req.body; // ดึงข้อมูลชื่อผู้ใช้และรหัสผ่านจาก request body

    // เข้ารหัสรหัสผ่านด้วย bcrypt
    bcrypt.hash(password, 10, function(err, hash) { // เข้ารหัสรหัสผ่านโดยใช้ bcrypt โดยตั้งค่า salt rounds เป็น 10 รอบ
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('Error hashing password:', err); // แสดงข้อความข้อผิดพลาดในการเข้ารหัสรหัสผ่าน
            res.status(500).send({ message: 'Error creating user', status: false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }

        // บันทึกข้อมูลผู้ใช้พร้อมรหัสผ่านที่เข้ารหัสลงในฐานข้อมูล
        const sql = "INSERT INTO customer (username, password) VALUES (?, ?)"; // สร้างคำสั่ง SQL เพื่อเพิ่มข้อมูลผู้ใช้ใหม่ลงในฐานข้อมูล
        db.query(sql, [username, hash], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับข้อมูลผู้ใช้ที่เข้ารหัสแล้วไปยังฐานข้อมูล
            if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
                console.error('Error creating user:', err); // แสดงข้อความข้อผิดพลาดถ้ามี
                res.status(500).send({ message: 'Error creating user', status: false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
                return; // ยุติการทำงานถ้ามีข้อผิดพลาด
            }
            res.send({ message: 'User created successfully', status: true }); // ส่งข้อความยืนยันการสร้างผู้ใช้สำเร็จกลับไปยัง client
        });
    });
});

// โหลดใบรับรอง SSL และกุญแจส่วนตัว
const options = {
    key: fs.readFileSync('privatekey.pem'), // อ่านไฟล์กุญแจส่วนตัวจากโฟลเดอร์ ssl
    cert: fs.readFileSync('certificate.pem') // อ่านไฟล์ใบรับรอง SSL จากโฟลเดอร์ ssl
};

// สร้างเซิร์ฟเวอร์ HTTPS
https.createServer(options, app).listen(port, function() {
    console.log(`server listening on port ${port} with HTTPS`); // แสดงข้อความใน console ว่าเซิร์ฟเวอร์กำลังทำงานอยู่ที่ port ใด และทำงานในโหมด HTTPS
});
