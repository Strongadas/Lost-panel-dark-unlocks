// add hovered class to selected list item
let list = document.querySelectorAll(".navigation li");

function activeLink() {
  list.forEach((item) => {
    item.classList.remove("hovered");
  });
  this.classList.add("hovered");
}

list.forEach((item) => item.addEventListener("mouseover", activeLink));

// Menu Toggle
let toggle = document.querySelector(".toggle");
let navigation = document.querySelector(".navigation");
let main = document.querySelector(".main");
const sms = document.getElementById('sms')

toggle.onclick = function () {
  navigation.classList.toggle("active");
  main.classList.toggle("active");
};

sms.addEventListener('click',()=>{
  sms.style.background = "green"
  sms.innerHTML = "Submting Order"
})

const imeiInput = document.getElementById('imei');
const imeiError = document.getElementById('imeiError');

imeiInput.addEventListener('input', function(event) {
  const enteredValue = event.target.value;
  if (enteredValue.length !== 15 || isNaN(enteredValue)) {
    imeiError.style.display = 'inline';
    imeiInput.setCustomValidity('Invalid IMEI');
  } else {
    imeiError.style.display = 'none';
    imeiInput.setCustomValidity('');
  }
});
//countries

document.getElementById('iphoneModel').addEventListener('change', function() {
  const selectedModel = this.value;
  document.getElementById('message').value = `Dear Customer,  
Your Lost ${selectedModel} has been temporarily switched ON. 
View location : 


FindMy Team`;
});

function displayStatus(status) {
  const statusDiv = document.getElementById('smsStatus');
  statusDiv.textContent = status;
}
