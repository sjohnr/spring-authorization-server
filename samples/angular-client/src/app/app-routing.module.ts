import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { IndexComponent } from './index/index.component';
import { AuthorizeComponent } from './authorize/authorize.component';

const routes: Routes = [
  { path: '', pathMatch: 'full', component: IndexComponent },
  { path: 'authorize', component: AuthorizeComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
