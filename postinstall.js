const message = `
                 1111111111
              1111111111111111
           1111111111111111111111
         11111111111111111111111111
       111111111111111       11111111
      1111111111111     111     111111
     1111111111111   111111111   111111
     111111111111   11111111111   111111
    1111111111111   11111111111   111111
    1111111111111   1111111111    111111
    1111111111111111111111111    1111111
    11111111                    11111111
     111111    111  1111111111111111111
     11111   11111  111111111111111111
      11111    1    11111111111111111
       111111     111111111111111111
         11111111111111111111111111
           1111111111111111111111
             111111111111111111
                 11111111111
 
    Thank you for using Parse Platform!
         https://parseplatform.org
 
Please consider donating to help us maintain
                this package:

👉 https://opencollective.com/parse-server 👈

`;

function main() {
  process.stdout.write(message);
  process.exit(0);
}

module.exports = main;
