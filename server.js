const express = require('express'); // เรียกใช้ express framework เพื่อสร้างเว็บแอปพลิเคชัน
const mysql = require('mysql2'); // เรียกใช้ไลบรารี mysql2 สำหรับเชื่อมต่อกับฐานข้อมูล MySQL
const app = express(); // สร้าง instance ของ express เพื่อใช้ในการกำหนดค่าต่าง ๆ ของแอปพลิเคชัน
const port = 3000; // กำหนด port ที่เซิร์ฟเวอร์จะรับฟังการเชื่อมต่อ
require('dotenv').config(); // เรียกใช้ dotenv เพื่อโหลด environment variables จากไฟล์ .env

// สร้างการเชื่อมต่อกับฐานข้อมูล MySQL โดยใช้ข้อมูลจาก environment variables
const db = mysql.createConnection({
    host: process.env.DB_HOST, // ชื่อโฮสต์ของฐานข้อมูล
    user: process.env.DB_USER, // ชื่อผู้ใช้สำหรับเข้าถึงฐานข้อมูล
    password: process.env.DB_PASSWORD, // รหัสผ่านสำหรับเข้าถึงฐานข้อมูล
    database: process.env.DB_NAME // ชื่อฐานข้อมูลที่ต้องการเชื่อมต่อ
});

db.connect(); // ทำการเชื่อมต่อกับฐานข้อมูล

app.use(express.json()); // กำหนดให้แอปพลิเคชันใช้ middleware ในการแปลงข้อมูลที่รับมาจาก client ให้เป็น JSON
app.use(express.urlencoded({ extended: true })); // กำหนดให้แอปพลิเคชันใช้ middleware ในการแปลงข้อมูลที่ส่งมาจาก client (เช่นฟอร์ม) ให้เป็น Object

// กำหนด route สำหรับการเพิ่มข้อมูลสินค้าลงในฐานข้อมูล
app.post('/product', function(req, res) {
    const { productName, productDetail, price, cost, quantity } = req.body; // ดึงข้อมูลที่ผู้ใช้ส่งมาใน request body
    const sql = "INSERT INTO product (productName, productDetail, price, cost, quantity) VALUES (?, ?, ?, ?, ?)"; // สร้างคำสั่ง SQL โดยใช้ placeholders เพื่อป้องกัน SQL Injection
    db.query(sql, [productName, productDetail, price, cost, quantity], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่าที่จะถูกแทนที่ใน placeholders ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error(err); // บันทึกข้อผิดพลาดใน console เพื่อการตรวจสอบ
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการบันทึกข้อมูล', 'status': false }); // ส่งข้อความแจ้งข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานหากเกิดข้อผิดพลาด
        }
        res.send({ 'message': 'บันทึกข้อมูลสำเร็จ', 'status': true }); // หากไม่มีข้อผิดพลาด ส่งข้อความยืนยันว่าบันทึกข้อมูลสำเร็จ
    });
});

// กำหนด route สำหรับการดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ productID
app.get('/product/:id', function(req, res) {
    const productID = req.params.id; // ดึง productID จากพารามิเตอร์ใน URL
    const sql = "SELECT * FROM product WHERE productID = ?"; // สร้างคำสั่ง SQL โดยใช้ placeholder เพื่อป้องกัน SQL Injection
    db.query(sql, [productID], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่า productID ที่จะถูกแทนที่ใน placeholder ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error(err); // บันทึกข้อผิดพลาดใน console เพื่อการตรวจสอบ
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการดึงข้อมูล', 'status': false }); // ส่งข้อความแจ้งข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานหากเกิดข้อผิดพลาด
        }
        res.send(result); // หากไม่มีข้อผิดพลาด ส่งผลลัพธ์จากการดึงข้อมูลกลับไปยัง client
    });
});

// กำหนด route สำหรับการเข้าสู่ระบบ
const bcrypt = require('bcrypt'); // เรียกใช้ไลบรารี bcrypt เพื่อเข้ารหัสและตรวจสอบรหัสผ่าน

app.post('/login', function(req, res) {
    const { username, password } = req.body; // ดึงชื่อผู้ใช้และรหัสผ่านจาก request body
    const sql = "SELECT * FROM customer WHERE username = ? AND isActive = 1"; // สร้างคำสั่ง SQL โดยใช้ placeholder เพื่อดึงข้อมูลผู้ใช้ที่ยังใช้งานอยู่
    db.query(sql, [username], function(err, result) { // ส่งคำสั่ง SQL พร้อมกับค่า username ที่จะถูกแทนที่ใน placeholder ไปยังฐานข้อมูล
        if (err) { // ตรวจสอบว่ามีข้อผิดพลาดหรือไม่
            console.error(err); // บันทึกข้อผิดพลาดใน console เพื่อการตรวจสอบ
            res.status(500).send({ 'message': 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', 'status': false }); // ส่งข้อความแจ้งข้อผิดพลาดกลับไปยัง client
            return; // ยุติการทำงานหากเกิดข้อผิดพลาด
        }
        if (result.length > 0) { // ตรวจสอบว่าพบข้อมูลผู้ใช้หรือไม่
            const customer = result[0]; // ดึงข้อมูลผู้ใช้จากผลลัพธ์ที่ได้
            bcrypt.compare(password, customer.password, function(err, match) { // ตรวจสอบรหัสผ่านที่เข้ารหัสด้วย bcrypt
                if (match) { // ถ้ารหัสผ่านถูกต้อง
                    customer['message'] = "เข้าสู่ระบบสำเร็จ"; // กำหนดข้อความยืนยันการเข้าสู่ระบบสำเร็จ
                    customer['status'] = true; // กำหนดสถานะเป็น true
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

app.listen(port, function() { // เริ่มต้นเซิร์ฟเวอร์และรับฟังการเชื่อมต่อที่ port ที่กำหนด
    console.log(`server listening on port ${port}`); // แสดงข้อความใน console ว่าเซิร์ฟเวอร์กำลังทำงานอยู่ที่ port ใด
});
