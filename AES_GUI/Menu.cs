using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AES_GUI
{
    public partial class Menu : Form
    {
        public Menu()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            this.Hide();
            KeyGenerator keyGenerator = new KeyGenerator();
            keyGenerator.Show();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Hide();
            IVGenerator iVGenerator = new IVGenerator();
            iVGenerator.Show();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            this.Hide();
            Encryptor encryptor = new Encryptor();
            encryptor.Show();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            this.Hide();
            Decryptor decryptor = new Decryptor();
            decryptor.Show();
        }

        public void comboBox1_SelectedIndexChanged() {}
    }
}
