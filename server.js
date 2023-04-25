
const express = require("express");
const app = express();
const {pool} = require("./dbConfig");
const path = require("path");
const bcrypt = require ("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const { request } = require("http");
const passport = require("passport");
const initializePassport = require("./passportConfig");
const fs = require('fs');
const crypto = require('crypto');
process.env.NLS_LANG = 'POLISH_POLAND.UTF8';
initializePassport(passport);
const PORT = process.env.PORT || 6020;


app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60 * 60 * 1000
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());


app.get("/", (req, res) =>{
    res.render("login");
});


app.get("/admin", checkNotAuthenticated, (req, res) => {
  pool.query('SELECT name, surname, email FROM appusers', function(error, results, fields) {
    if (error) throw error;
    const users = results.rows.map(row => ({
      name: row.name,
      surname: row.surname,
      email: row.email
    }));
    let index = 0;
    res.render('admin', { users, index });
  });
});

app.get("/galeriafotopulapki", checkNotAuthenticated, (req, res) => {
    res.render("galeriafotopulapki");
});

app.post('/users/rejestracja', async (req, res) => {
    let { name, surname, email, password } = req.body;
    console.log({
      name,
      surname,
      email,
      password
    })
    let errors = [];
  
    if (!name || !surname || !email || !password) {
      errors.push({ message: "Wypełnij wszystkie pola !!" });
    }
    if (password.length < 4) {
      errors.push({ message: "Hasło powinno mieć przynajmniej 4 znaki" });
    }
  
    if (errors.length > 0) {
      res.render("admin", { errors });
    } else {
      let cryptedpassword = await bcrypt.hash(password, 2);
      console.log(cryptedpassword);
      pool.query(
        `SELECT * FROM appusers 
        WHERE email = $1`, [email], (err, result) => {
          if (err) {
            throw err
          }
          console.log(result.rows);
          if (result.rows.length > 0) {
            errors.push({ message: "Taki email jest już w systemie !!" })
            res.render("admin", { errors });
          } else {
            pool.query(
              `INSERT INTO appusers (name, surname, email, password)
                VALUES ($1, $2, $3, $4)
                RETURNING id, password`, [name, surname, email, password],
              (err, results) => {
                if (err) {
                  throw err;
                }
                console.log(results.rows);
                console.log("nowy uzytkownik w bazie") 
                req.flash("success_msg", "Zostałeś zarejestrowany");
                res.redirect("/admin");
              })
          }}
      )}
  });


app.post("/logowanie", 
passport.authenticate("local",{
    successRedirect: "/admin",
    failureRedirect: "/",
    failureFlash:true
}));

app.post("/wylogowanie", (req, res) =>{
  req.logout(() => {
      req.flash("success_msg", "Uzytkownik wylogowany");
      res.redirect("/");
    });
  console.log("wylogowano uzytkownika")
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    } 
    res.redirect("/users/logowanie");
  }

function checkNotAuthenticated (req,res,next) {
    if (req.isAuthenticated()){
        return next()
    }
    res.redirect("/users/logowanie");
}

app.listen(PORT, ()=>{console.log(`Serwer na porcie ${PORT}`);});
app.use(express.static(path.join(__dirname, 'public')));