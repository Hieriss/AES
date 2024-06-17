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
    public partial class IVGenerator : Form
    {
        [DllImport("E:\\Workspace\\AES\\AES_DLL\\x64\\Debug\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "IVGen")]
        public static extern void IVGen(string iv_length, string file_name);

        public IVGenerator()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string iv_length = comboBox1.SelectedItem.ToString();
            string file_name = textBox2.Text;
            if (iv_length == "")
            {
                MessageBox.Show("Please select your key length!");
            }
            if (file_name == "")
            {
                MessageBox.Show("Please enter your file name!");
            }
            IVGen(iv_length, file_name);
            MessageBox.Show("Key generated successfully!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
