const express = require('express'); // เรียกใช้ Express framework เพื่อสร้างเว็บแอปพลิเคชัน
const mysql = require('mysql2'); // เรียกใช้ไลบรารี MySQL2 สำหรับเชื่อมต่อกับฐานข้อมูล MySQL
const helmet = require('helmet'); // เพิ่ม helmet เพื่อป้องกันการโจมตีผ่าน HTTP headers
const rateLimit = require('express-rate-limit'); // เพิ่ม rate limiting เพื่อป้องกัน DDoS
const bcrypt = require('bcrypt'); // ใช้ bcrypt สำหรับการเข้ารหัสรหัสผ่าน
const https = require('https'); // เรียกใช้โมดูล https เพื่อสร้างเซิร์ฟเวอร์ HTTPS
const fs = require('fs'); // ใช้ fs เพื่ออ่านไฟล์
require('dotenv').config(); // โหลด environment variables จากไฟล์ .env

const app = express(); // สร้าง instance ของ Express เพื่อใช้กำหนดค่าต่างๆ ของแอปพลิเคชัน
const port = process.env.PORT || 3000; // กำหนด port ที่เซิร์ฟเวอร์จะรับฟังการเชื่อมต่อ โดยใช้ค่าจาก .env หรือใช้ port 3000 เป็นค่าเริ่มต้น

// เพิ่ม Helmet เพื่อป้องกันการโจมตีทั่วไปที่เกี่ยวกับ HTTP headers
app.use(helmet());

// เพิ่ม Rate Limiting ทั่วไปเพื่อป้องกันการโจมตีแบบ DDoS
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 100, // จำกัดการร้องขอ 100 ครั้งต่อ IP ต่อ 15 นาที
});
app.use(generalLimiter); // ใช้ middleware ที่ตั้งค่า Rate Limiting ไว้

// ใช้ middleware สำหรับแปลงข้อมูล JSON ที่รับมาจาก client เป็น Object
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // ใช้สำหรับแปลงข้อมูลฟอร์ม URL-encoded ที่ส่งมาจาก client เป็น Object

// สร้างการเชื่อมต่อกับฐานข้อมูล MySQL โดยใช้ข้อมูลจาก environment variables
const db = mysql.createConnection({
    host: process.env.DB_HOST, // ชื่อโฮสต์ของฐานข้อมูล รับค่าจาก environment variables
    user: process.env.DB_USER, // ชื่อผู้ใช้สำหรับเข้าถึงฐานข้อมูล รับค่าจาก environment variables
    password: process.env.DB_PASSWORD, // รหัสผ่านสำหรับเข้าถึงฐานข้อมูล รับค่าจาก environment variables
    database: process.env.DB_NAME, // ชื่อฐานข้อมูลที่ต้องการเชื่อมต่อ รับค่าจาก environment variables
    ssl: { rejectUnauthorized: false } // ปิดการตรวจสอบใบรับรอง SSL เพื่อหลีกเลี่ยงข้อผิดพลาดการเชื่อมต่อ (ใช้ในสภาพแวดล้อมการพัฒนาเท่านั้น)
});

db.connect((err) => { // ทำการเชื่อมต่อกับฐานข้อมูล
    if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
        console.error('ไม่สามารถเชื่อมต่อฐานข้อมูลได้:', err); // แสดงข้อความข้อผิดพลาดถ้าไม่สามารถเชื่อมต่อได้
        process.exit(1); // ปิดการทำงานของโปรแกรมถ้าไม่สามารถเชื่อมต่อฐานข้อมูลได้
    }
    console.log('เชื่อมต่อฐานข้อมูลสำเร็จ'); // แสดงข้อความเมื่อเชื่อมต่อฐานข้อมูลได้สำเร็จ
});

// เพิ่ม Rate Limiting เฉพาะสำหรับการเข้าสู่ระบบ
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 10, // จำกัดการพยายามเข้าสู่ระบบ 10 ครั้งต่อ IP ต่อ 15 นาที
    message: {
        status: false,
        message: "พยายามเข้าสู่ระบบเกินจำนวนครั้งที่กำหนด โปรดลองใหม่อีกครั้งในภายหลัง"
    }
});

// กำหนด route สำหรับการเข้าสู่ระบบ
app.post('/login', loginLimiter, function(req, res) { // ใช้ loginLimiter เฉพาะสำหรับการร้องขอเข้าสู่ระบบ
    const { username, password } = req.body; // ดึงชื่อผู้ใช้และรหัสผ่านจาก request body
    const sql = "SELECT * FROM customer WHERE username = ? AND isActive = 1"; // สร้างคำสั่ง SQL โดยใช้ placeholder เพื่อดึงข้อมูลผู้ใช้ที่ยังใช้งานอยู่เท่านั้น
    db.query(sql, [username], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่า username ที่จะถูกแทนที่ใน placeholder ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('ข้อผิดพลาดในการเข้าสู่ระบบ:', err); // แสดงข้อความข้อผิดพลาดใน console
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        if (result.length > 0) { // ตรวจสอบว่าพบข้อมูลผู้ใช้หรือไม่
            const customer = result[0]; // ดึงข้อมูลผู้ใช้จากผลลัพธ์ที่ได้
            bcrypt.compare(password, customer.password, function(err, match) { // ตรวจสอบรหัสผ่านที่เข้ารหัสด้วย bcrypt ว่าตรงกับข้อมูลในฐานข้อมูลหรือไม่
                if (match) { // ถ้ารหัสผ่านถูกต้อง
                    customer['message'] = "เข้าสู่ระบบสำเร็จ"; // กำหนดข้อความยืนยันการเข้าสู่ระบบสำเร็จ
                    customer['status'] = true; // กำหนดสถานะเป็น true เพื่อระบุว่าการเข้าสู่ระบบสำเร็จ
                    res.send(customer); // ส่งข้อมูลผู้ใช้กลับไปยัง client พร้อมกับสถานะสำเร็จ
                } else { // ถ้ารหัสผ่านไม่ถูกต้อง
                    res.send({ "message": "กรุณาระบุรหัสผ่านใหม่อีกครั้ง", "status": false }); // ส่งข้อความแจ้งว่ารหัสผ่านไม่ถูกต้องพร้อมกับสถานะที่ไม่สำเร็จ
                }
            });
        } else { // ถ้าไม่พบข้อมูลผู้ใช้ในฐานข้อมูล
            res.send({ "message": "กรุณาระบุรหัสผ่านใหม่อีกครั้ง", "status": false }); // ส่งข้อความแจ้งว่ารหัสผ่านไม่ถูกต้อง พร้อมกับสถานะที่ไม่สำเร็จ
        }
    });
});

// กำหนด route สำหรับการเพิ่มข้อมูลสินค้าใหม่ลงในฐานข้อมูล
app.post('/product', function(req, res) {
    const { productName, productDetail, price, cost, quantity } = req.body; // ดึงข้อมูลที่ผู้ใช้ส่งมาใน request body
    const sql = "INSERT INTO product (productName, productDetail, price, cost, quantity) VALUES (?, ?, ?, ?, ?)"; // สร้างคำสั่ง SQL โดยใช้ placeholders เพื่อป้องกัน SQL Injection
    db.query(sql, [productName, productDetail, price, cost, quantity], function(err, result) { // ส่งคำสั่ง SQL และค่าที่จะถูกแทนที่ใน placeholders ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('ข้อผิดพลาดในการบันทึกข้อมูล:', err); // แสดงข้อความข้อผิดพลาดใน console
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการบันทึกข้อมูล', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        res.send({ 'message': 'บันทึกข้อมูลสำเร็จ', 'status': true }); // ส่งข้อความยืนยันการบันทึกสำเร็จกลับไปยัง client
    });
});

// กำหนด route สำหรับการดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ productID
app.get('/product/:id', function(req, res) {
    const productID = req.params.id; // ดึง productID จากพารามิเตอร์ใน URL
    const sql = "SELECT * FROM product WHERE productID = ?"; // สร้างคำสั่ง SQL โดยใช้ placeholder เพื่อป้องกัน SQL Injection
    db.query(sql, [productID], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่า productID ที่จะถูกแทนที่ใน placeholder ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('ข้อผิดพลาดในการดึงข้อมูล:', err); // แสดงข้อความข้อผิดพลาดใน console
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการดึงข้อมูล', 'status': false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }
        res.send(result); // ส่งผลลัพธ์จากการดึงข้อมูลกลับไปยัง client
    });
});

// กำหนด route สำหรับการสร้างผู้ใช้ใหม่พร้อมเข้ารหัสรหัสผ่าน
app.post('/register', function(req, res) {
    const { username, password } = req.body; // ดึงข้อมูลชื่อผู้ใช้และรหัสผ่านจาก request body

    // เข้ารหัสรหัสผ่านด้วย bcrypt
    bcrypt.hash(password, 10, function(err, hash) { // เข้ารหัสรหัสผ่านโดยใช้ bcrypt ด้วยจำนวนรอบการ salt 10 รอบ
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error('Error hashing password:', err); // แสดงข้อความข้อผิดพลาดใน console
            res.status(500).send({ message: 'Error creating user', status: false }); // ส่งข้อความข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานถ้ามีข้อผิดพลาด
        }

        // บันทึกข้อมูลผู้ใช้พร้อมรหัสผ่านที่เข้ารหัสลงในฐานข้อมูล
        const sql = "INSERT INTO customer (username, password) VALUES (?, ?)"; // สร้างคำสั่ง SQL สำหรับเพิ่มข้อมูลผู้ใช้ใหม่
        db.query(sql, [username, hash], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่าที่จะถูกแทนที่ใน placeholders ไปยังฐานข้อมูล
            if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
                console.error('Error creating user:', err); // แสดงข้อความข้อผิดพลาดใน console
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
    console.log(`server listening on port ${port} with HTTPS`); // แสดงข้อความใน console ว่าเซิร์ฟเวอร์กำลังทำงานอยู่ที่ port ใด
});
