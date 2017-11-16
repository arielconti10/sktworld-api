<?php

use Illuminate\Database\Seeder;

class UserTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        factory(\App\User::class)->create([
            'name' => 'user',
            'email' => 'user@user.com',
            'password' => bcrypt(123456)
        ]);
    }
}
