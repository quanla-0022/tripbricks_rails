//= require angular
//= require jquery3

var appTripbricks = angular.module("appTripbricks", [])
.controller("myCtrl", ["$scope", function($scope) {
    $scope.myValue ="";
    $scope.myFunc = function() {
        $(".autocomplete_list").removeClass("hidden");
    };
}]);

$(document).ready(function() {
    var owl = $("#carousel-place-home");
    owl.owlCarousel({
        items: 1,
        loop: true,
        margin: 10,
        autoPlay: true,
        autoPlayTimeout: 5000,
        autoPlayHoverPause: true
    });

    var owlHotel = $("#carousel-place-hotel");
    owlHotel.owlCarousel({
        items: 1,
        loop: true,
        margin: 10,
        dots: false,
        pagination: false,
        autoPlay: true,
        autoPlayTimeout: 5000,
        autoPlayHoverPause: true
    });
    // Photo slider
    var owlPhoto = $("#photo-slider");
    owlPhoto.owlCarousel({
        items:4,
        responsive:{
            0:{
                items:1
            },
            600:{
                items:2
            },
            1000:{
                items:3
            },
            1200:{
                items:4
            }
        },
        loop:true,
        margin:10,
        nav:true,
        pagination: true,
        autoPlay: true,
        autoPlayTimeout: 5000,
        autoPlayHoverPause: true
    });
    // Link images

    var owlLinkimage = $(".link-images-slider");
    owlLinkimage.owlCarousel({
        items: 6,
        responsive:{
            0:{
                items:1
            },
            600:{
                items:2
            },
            1000:{
                items:3
            },
            1200:{
                items:6
            }
        },
        loop: true,
        margin: 10,
        autoPlay: true,
        pagination: false,
        merge: true,
        autoPlayTimeout: 10000,
        autoPlayHoverPause: true
    });
});
