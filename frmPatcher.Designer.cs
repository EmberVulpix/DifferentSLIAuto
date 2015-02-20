namespace DifferentSLIAuto
{
    partial class frmPatcher
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(frmPatcher));
            this.btnPatch = new System.Windows.Forms.Button();
            this._listBox = new System.Windows.Forms.ListBox();
            this.SuspendLayout();
            // 
            // btnPatch
            // 
            this.btnPatch.Location = new System.Drawing.Point(284, 113);
            this.btnPatch.Name = "btnPatch";
            this.btnPatch.Size = new System.Drawing.Size(75, 23);
            this.btnPatch.TabIndex = 0;
            this.btnPatch.Text = "Patch!";
            this.btnPatch.UseVisualStyleBackColor = true;
            this.btnPatch.Click += new System.EventHandler(this.btnPatch_Click);
            // 
            // _listBox
            // 
            this._listBox.Location = new System.Drawing.Point(12, 12);
            this._listBox.Name = "_listBox";
            this._listBox.Size = new System.Drawing.Size(619, 95);
            this._listBox.TabIndex = 1;
            // 
            // frmPatcher
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(643, 141);
            this.Controls.Add(this._listBox);
            this.Controls.Add(this.btnPatch);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "frmPatcher";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "DifferentSLI Patcher v1.3 by Ember 2k15!";
            this.Load += new System.EventHandler(this.frmPatcher_Load);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button btnPatch;
        private System.Windows.Forms.ListBox _listBox;
    }
}

