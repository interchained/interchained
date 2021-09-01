const Toast = Swal.mixin({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    onOpen: (toast) => {
        toast.addEventListener('mouseenter', Swal.stopTimer)
        toast.addEventListener('mouseleave', Swal.resumeTimer)
    }
})

Vue.use(VueLoading);
Vue.component('loading', VueLoading)
Vue.component(VueCountdown.name, VueCountdown);

var app = new Vue({  

    el: "#root",
    data: {
        currentPage: 'start',
        completed: false,
        expired: false,
        error: false,
        pay: 'Pay',
        coin: '',
        coins: [],
        amount: 50,
        selected: undefined,
        invoice: [],
        isactive: undefined,
        rates: [],
        submit: false,
        email: '',
        reg: /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,24}))$/
    },

    mounted: function() {
        console.log("Vue.js is running...");
        this.getAllcoins();

    },

    computed: {
        isDisabled: function() {
            return !this.submit;
        },


    },

    methods: {

      getAllcoins: function () {
      axios.get('api.php?coins&amount='+this.amount)
      .then(function (response) {
        console.log(response);

        if (response.data.error) {
          console.log(response);
        } else {
          app.coins = response.data;
        }
      })
    },


      setActive(name) { 
             app.isactive = name;
             name != null ? this.pay = 'Pay with ' + name : this.pay = 'Pay';
             name != null ? this.submit = true : this.submit = false;
             let selectCoin = this.coins.filter(coins => coins.name === name);
             this.coin = selectCoin[0].coin;

        },



        paymentSubmit: function() {
            if (!this.reg.test(this.email)) {
                Toast.fire({
                    icon: 'error',
                    title: 'Please provide a valid email address'
                })
            } else {

                let loader = this.$loading.show({
                    // Optional parameters
                    container: this.fullPage ? null : this.$refs.formContainer,
                    canCancel: true,
                    onCancel: this.onCancel,
                });

                axios.get('api.php?amount=' + this.amount + '&coin=' + this.coin)
                    .then(response => {
                        if (response.data.error) {
                            console.log(response.data.error);
                        } else {
                            app.invoice = response.data;
                            console.log(app.invoice);
                        }
                    })
                    .catch(e => {
                        console.log(e);
                    })

                setTimeout(() => {
                    app.currentPage = 'payment';
                    this.processInvoice();
                    loader.hide()
                }, 5000)

            }

        },

        isEmailValid: function() {
            return (this.email == "") ? "" : (this.reg.test(this.email)) ? 'is-valid' : 'is-invalid';
        },


        processInvoice: function() {

            let pageStatus = app.currentPage;

            if (pageStatus === 'payment') {


                setInterval(() => {

                    axios.get('api.php?invoice=' + this.invoice.invoice)
                        .then(function(response) {

                            if (response.data.paid === '1' || response.data.paid === '2') {

                                app.currentPage = 'confirmed';
                               

                            } else if (response.data.error) {
                                app.currentPage = 'error';

                            }

                        })

                }, 5000);

            }




        },

        handleCountdownProgress(data) {
            if (data.seconds <= 0) {
                this.invoiceExpired();
            }
        },

        invoiceExpired(data) {
            app.currentPage = 'expired';
        },

        onCancel() {
            console.log('User cancelled the loader.')
        }
    }

});