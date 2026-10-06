const searchBar = document.querySelector('#searchBar');
const getBtn = document.querySelector('#getBtn');
const responseArea = document.querySelector('#responseArea');
let appName;
let user;
let issuer;

//VP may be in the URL parameters after redirecting from User to App

$(document).ready(() => {
    $.ajax({
                    method: "GET",
                    url: "/generateInvitation",
                    success: async function (data) {
                        $("#invitation").html(data.url)
                        $("#invitation").append("<img src=\"" + data.qrcode + "\">");
                    }
                });
})
